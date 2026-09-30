# -*- coding: utf-8 -*-
"""输出侧检查（发布前）——**默认只告警，不拦截**。

抓取层扫描器只能说「这条原料里有指令样文字」；真正要紧的是**指令有没有生效**，
而生效的痕迹一定落在即将公开的那部分输出里。本模块查六类痕迹：

  ① 未授权外链：公开区里所有会被浏览器当成地址的写法（清单见 extract_links），
     既不在本批原料的 url 集合里、注册域名也不在已知域名白名单里。
     另查：javascript:/vbscript:/data: 伪协议、裸 IP、锚文本写 A 域名而 href 指向 B 域名。
  ② 规程/提示词原文片段：公开区出现与调用方给出的规则文本连续 ≥30 字一致的片段
     （可扣掉与输出骨架模板共有的片段）。
  ③ 金丝雀：CANARY-… 出现在公开区。
  ④ 围栏外泄：UNTRUSTED-DATA 分隔符或 nonce 出现在公开区。
  ⑤ 私有内容：调用方给出的私有句式 / 私有原文指纹出现在公开区。
  ⑥ 零宽/隐藏文字，以及污点追踪：抓取层标记过的条目里「指令所在句」要求写出的
     记号 / 引号串 / URL，原样出现在公开区 → 说明那条指令被执行了。

本模块**不读任何文件**：白名单、规则文本、私有文本都由调用方传入。

所有对输出的切分（私有区、标签、注释、CSS）都是单遍线性扫描，不用 `.*?` 跨越整段输出，
避免构造输入下的平方级耗时。

为什么默认不拦截：新检查的误报率需要先在自己的历史输出上观察一段时间；
一个会误报的阻断闸门会训练出「看到红灯先想怎么绕」。设 enforce=True
（或环境变量 INJECTION_GUARD_ENFORCE=1）时，Report.blocked 在有发现时为 True。
"""
from __future__ import annotations

import html as _html
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Sequence
from urllib.parse import urlsplit

from .scan import normalize, scan_item

# ─────────────────────────── 区域切分 ───────────────────────────
# 约定：输出里 PRIVATE_START … PRIVATE_END 之间是私有区（不发布）。
# 公开区不是「私有区开始标记之前」——结束标记之后的内容同样会被发布。
# 标记可以换：make_public_region(start, end) 返回对应的切分函数，传给 check_html(strip_private=...)。
# **发布端必须用同一个函数删掉私有块**；否则检查器看到的公开区和实际发布的内容不一致。
PRIVATE_START = "<!-- private:begin -->"
PRIVATE_END = "<!-- private:end -->"


def _marker_rx(marker: str) -> "re.Pattern[str]":
    """HTML 注释形式的标记容忍内部空白与大小写差异；其他形式按字面匹配（忽略大小写）。"""
    m = re.fullmatch(r"<!--\s*(.*?)\s*-->", marker.strip(), re.S)
    if m:
        return re.compile(r"<!--\s*" + re.escape(m.group(1)) + r"\s*-->", re.I)
    return re.compile(re.escape(marker), re.I)


def _private_spans(html: str, start_rx: "re.Pattern[str]", end_rx: "re.Pattern[str]") -> list[tuple[int, int]]:
    """线性扫描：每个开始标记配对它之后最近的结束标记。

    没有结束标记的开始标记不构成私有块，其后的内容按公开处理（检查器宁可多查）。
    一旦找不到结束标记就停止——后面不可能再有完整的块，扫描不回头。
    """
    spans, pos = [], 0
    while True:
        ms = start_rx.search(html, pos)
        if not ms:
            break
        me = end_rx.search(html, ms.end())
        if not me:
            break
        spans.append((ms.start(), me.end()))
        pos = me.end()
    return spans


def make_public_region(start: str = PRIVATE_START, end: str = PRIVATE_END) -> Callable[[str], str]:
    """返回「去掉所有私有块、其余都算公开」的切分函数。发布端与检查器应共用它。"""
    srx, erx = _marker_rx(start), _marker_rx(end)

    def _public(html: str) -> str:
        spans = _private_spans(html, srx, erx)
        if not spans:
            return html
        out, prev = [], 0
        for a, b in spans:
            out.append(html[prev:a])
            prev = b
        out.append(html[prev:])
        return "".join(out)
    _public.__doc__ = f"去掉 {start} … {end} 私有块后的全部内容。"
    return _public


public_region = make_public_region()
public_region.__doc__ = "默认的公开区定义：去掉所有 <!-- private:begin --> … <!-- private:end --> 块，其余都算会被发布。"


def private_region(html: str, start: str = PRIVATE_START, end: str = PRIVATE_END) -> str:
    spans = _private_spans(html, _marker_rx(start), _marker_rx(end))
    return "\n".join(html[a:b] for a, b in spans)


# ─────────────────────────── 线性 HTML 切分 ───────────────────────────
_TAG_START = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9:_.-]*)")
_TAG_NAME_RUN = re.compile(r"[^=>]*")          # 标签内到下一个 = 或 > 为止
_WS = re.compile(r"\s*")
_RAWTEXT = ("script", "style")


class _Finder:
    """带记忆的 str.find：同一个 needle 只会被向后查找一遍（找不到就记住，之后不再扫）。"""

    def __init__(self, s: str, needle: str):
        self.s, self.needle, self.at = s, needle, -2          # -2 = 还没查过；-1 = 之后再没有

    def next(self, pos: int) -> int:
        if self.at == -1 or (self.at >= pos):
            return self.at
        self.at = self.s.find(self.needle, pos)
        return self.at


def _comment_end(s: str, lt: int, f1: "_Finder", f2: "_Finder") -> int:
    """<!-- 开始的注释在哪里结束：<!--> / <!---> 是空注释；--> 与 --!> 都能闭合；没有闭合则到文末。"""
    if s.startswith("<!-->", lt):
        return lt + 5
    if s.startswith("<!--->", lt):
        return lt + 6
    ends = [e + len(f.needle) for f in (f1, f2) for e in [f.next(lt + 4)] if e >= 0]
    return min(ends) if ends else len(s)


def _tokens(s: str) -> Iterator[tuple[str, int, int, str, bool]]:
    """单遍线性切分 HTML：产出 (kind, start, end, tag_name, is_closing)。

    kind = text / tag / comment / raw（script、style 的内容）。
    未闭合的注释、script/style、属性引号都延伸到文末（与浏览器一致）；
    每次查找都从当前位置向后且找到后越过，找不到就结束 → 总耗时 O(n)。
    只有紧跟在 `=` 后面的引号才算属性值引号（`<b x=a'>` 里的 ' 不开启引号）。
    """
    n, i, text_start = len(s), 0, 0
    low = None
    c1, c2, gt = _Finder(s, "-->"), _Finder(s, "--!>"), _Finder(s, ">")
    while i < n:
        lt = s.find("<", i)
        if lt < 0:
            break
        if s.startswith("<!--", lt):
            end = _comment_end(s, lt, c1, c2)
            if lt > text_start:
                yield ("text", text_start, lt, "", False)
            yield ("comment", lt, end, "", False)
            i = text_start = end
            continue
        if s.startswith(("<!", "<?"), lt):           # doctype / 伪注释：到下一个 >
            e = gt.next(lt + 2)
            end = n if e < 0 else e + 1
            if lt > text_start:
                yield ("text", text_start, lt, "", False)
            yield ("comment", lt, end, "", False)
            i = text_start = end
            continue
        m = _TAG_START.match(s, lt)
        if not m:
            i = lt + 1
            continue
        j = m.end()
        while True:
            j = _TAG_NAME_RUN.match(s, j).end()
            if j >= n:
                end = n
                break
            if s[j] == ">":
                end = j + 1
                break
            j = _WS.match(s, j + 1).end()          # s[j] == "="
            if j < n and s[j] in "\"'":
                q = s.find(s[j], j + 1)
                if q < 0:
                    j = n
                    continue
                j = q + 1
        if lt > text_start:
            yield ("text", text_start, lt, "", False)
        name, closing = m.group(2).lower(), bool(m.group(1))
        yield ("tag", lt, end, name, closing)
        i = text_start = end
        if not closing and name in _RAWTEXT and end < n:
            if low is None:
                low = s.lower()
            e = low.find("</" + name, end)
            stop = n if e < 0 else e
            yield ("raw", end, stop, name, False)
            i = text_start = stop
    if text_start < n:
        yield ("text", text_start, n, "", False)


def html_text(seg: str) -> str:
    """HTML → 纯文本（去 script/style/注释/标签）。纯文本输入原样返回（仅做实体反转义）。"""
    if "<" not in seg:
        return _html.unescape(seg)
    parts = []
    for kind, a, b, _, _ in _tokens(seg):
        parts.append(seg[a:b] if kind == "text" else " ")
    return _html.unescape("".join(parts))


def norm_text(s: str) -> str:
    """去空白与常见标点差异后比对（规则文本常是折行排版的）。"""
    return re.sub(r"[\s　*`>#|_\-—·•]+", "", s)


# ─────────────────────────── 域名 ───────────────────────────
_SLD2 = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.kr", "or.kr", "co.uk", "org.uk",
         "com.hk", "com.tw", "co.jp", "ne.jp", "or.jp", "com.au", "com.sg", "co.in", "com.br"}
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def host_of(url: str) -> str:
    try:
        h = urlsplit(url if "//" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    return h.lower().rstrip(".")


def reg_domain(host: str) -> str:
    """粗略的注册域名（不依赖公共后缀表；只内置常见二级后缀）。"""
    host = (host or "").lower()
    if not host or _IP.match(host):
        return host
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _SLD2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def known_domains(urls: Iterable[str] = (), texts: Iterable[str] = (),
                  domains: Iterable[str] = ()) -> set[str]:
    """构造已知良性域名集合（注册域名）。

    urls:    信源配置里的地址、历史原料里的 url 字段等；
    texts:   历史输出（HTML 或纯文本），用与检查时相同的 extract_links 抽出所有外链；
    domains: 直接给出的域名（会归一到注册域名）。

    建议白名单用「见过的域名史」，不是「今天见过的」：钓鱼域名的特征是从没出现过。
    历史输出只取**本批之前**的——当批输出里的外链不能给自己作保。
    """
    out = {reg_domain(host_of(canonical_url(u) or u)) for u in urls if u}
    for t in texts:
        out |= {reg_domain(host_of(L["url"])) for L in extract_links(t)}
    out |= {reg_domain(d.lower().strip(".")) for d in domains if d}
    out -= {""}
    return out


def _brands(domains: Iterable[str]) -> tuple[str, ...]:
    """白名单注册域名的主标签（≥4 字符），用来点名「疑似仿冒哪家」。"""
    return tuple(sorted({d.split(".")[0] for d in domains if len(d.split(".")[0]) >= 4}))


# ─────────────────────────── 链接抽取 ───────────────────────────
_SCHEME_BAD = re.compile(r"^\s*(?:javascript|vbscript|data)\s*:", re.I)
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):")
_SPECIAL = {"http", "https", "ftp", "ws", "wss"}
_C0_SPACE = "".join(chr(i) for i in range(0x21))
_TAB_NL = re.compile(r"[\t\n\r]")

# 会被浏览器当成地址来用的属性：伪协议只在这些属性里算数（alt/title 里写 "javascript: 入门" 不算）
_URL_ATTRS = {"href", "src", "action", "formaction", "poster", "background", "data", "cite", "codebase",
              "longdesc", "lowsrc", "dynsrc", "manifest", "icon", "to", "from", "values", "xlink:href",
              "srcset", "imagesrcset", "ping", "content"}

# 全文兜底扫描（不依赖标签切分）：注释里、被错切的标签里、脚本字符串里的这类写法也会被看到
_ATTR_CORE = re.compile(r"""\b(href|src|action|formaction|srcset|imagesrcset|poster|background|ping)"""
                        r"""\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))""", re.I)
# 标签内属性：名字只在空白 / 引号 / 斜杠之后开始（避免长串名字字符的平方级回溯）
_ATTR_IN_TAG = re.compile(r"""(?<![^\s"'/])([^\s"'>/=]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))""")
_CSS_URL = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)"'\s]*))""", re.I)
_CSS_STR = re.compile(r""""([^"\n]*)"|'([^'\n]*)'""")
_CSS_ESC = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\r\n\f]?|(\n)|(.))", re.S)
_JS_STR = re.compile(r""""([^"\n]*)"|'([^'\n]*)'|`([^`]*)`""")
_REFRESH_HEAD = re.compile(r"\s*[\d.]+\s*[;,]")
_REFRESH_URL = re.compile(r"\burl\s*=\s*", re.I)
_AUTOLINK = re.compile(r"<((?:https?|ftp)://[^\s<>\"']+)>", re.I)
_BARE = re.compile(r"(?:https?://|www\.)[^\s<>\"'）)】」，。；]+", re.I)
_MD = re.compile(r"\[[^\]\n]{0,120}\]\(\s*<?((?:https?:|www\.|//|/\\|\\\\|\\/)[^)\s>]+)")


def canonical_url(u: str) -> str:
    """按浏览器的宽松解析把地址规整成可比较的形式；相对地址返回空串。

      · 去掉首尾空白/控制字符，删掉中间的 \\t \\n \\r（浏览器也这么做）；
      · 反斜杠当正斜杠：`/\\evil`、`\\\\evil`、`\\/evil` 都等于 `//evil`；
      · `//host` 协议相对 → `https://host`；`https:evil`、`https:/evil` → `https://evil`；
      · 伪协议原样返回（由调用方判定）；mailto:/tel: 等其他协议、相对路径返回空串。
    """
    u = _TAB_NL.sub("", (u or "").strip(_C0_SPACE))
    if not u:
        return ""
    if _SCHEME_BAD.match(u):
        return u
    u = u.replace("\\", "/")
    m = _SCHEME.match(u)
    if m:
        scheme = m.group(1).lower()
        if scheme in _SPECIAL:
            rest = u[m.end():].lstrip("/")
            return f"{scheme}://{rest}" if rest else ""
        rest = u[m.end():]
        return f"{scheme}:{rest}" if rest.startswith("//") else ""
    if u.startswith("//"):
        rest = u.lstrip("/")
        return f"https://{rest}" if rest else ""
    return ""


def _strip_css_comments(css: str) -> str:
    out, i = [], 0
    while True:
        a = css.find("/*", i)
        if a < 0:
            out.append(css[i:])
            break
        out.append(css[i:a])
        b = css.find("*/", a + 2)
        if b < 0:                                    # 未闭合注释吞到文末（与 CSS 解析一致）
            break
        i = b + 2
    return " ".join(out)


def _css_unescape(css: str) -> str:
    def rep(m):
        if m.group(1):
            cp = int(m.group(1), 16)
            return chr(cp) if 0 < cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF else "�"
        if m.group(2):
            return ""
        return m.group(3)
    return _CSS_ESC.sub(rep, css)


class _Links:
    """按规整后的地址去重；保留第一次出现的写法与来源。"""

    def __init__(self):
        self.items: list[dict] = []
        self.index: dict[str, dict] = {}
        self.prefix = ""                                 # srcdoc 递归时标注来源

    def add(self, raw: str, via: str, url_attr: bool = True) -> None:
        via = self.prefix + via
        c = canonical_url(raw)
        if not c:
            return
        if _SCHEME_BAD.match(c):
            if not url_attr:
                return
            key, entry = c.strip().lower(), {"url": c.strip(), "raw": raw.strip(), "via": via, "anchor": ""}
        else:
            h = host_of(c)
            if not h or any(ch.isspace() for ch in h):   # 「https: 协议介绍」这类不是合法地址
                return
            key, entry = c, {"url": c, "raw": raw.strip(), "via": via, "anchor": ""}
        if key not in self.index:
            self.index[key] = entry
            self.items.append(entry)


def _from_css(css: str, L: _Links, via: str) -> None:
    css = _css_unescape(_strip_css_comments(css))
    for m in _CSS_URL.finditer(css):
        L.add(next((g for g in m.groups() if g is not None), ""), via)
    for m in _CSS_STR.finditer(css):                 # @import "…"、image-set("…" 1x)、content: "…"
        L.add(m.group(1) if m.group(1) is not None else m.group(2), via)


def _from_script(js: str, L: _Links, via: str) -> None:
    for m in _JS_STR.finditer(js):
        v = next((g for g in m.groups() if g is not None), "")
        L.add(v.replace("\\/", "/"), via, url_attr=False)
    for m in _BARE.finditer(js):
        L.add(m.group(0).rstrip(".,;:"), via, url_attr=False)


def _from_attr(name: str, raw_val: str, L: _Links, depth: int) -> None:
    name = name.lower()
    if name == "xmlns" or name.startswith("xmlns:"):
        return
    v = _html.unescape(raw_val)
    if name == "style":
        _from_css(v, L, "css")
    elif name in ("srcset", "imagesrcset"):
        for cand in v.split(","):
            tok = cand.split()
            if tok:
                L.add(tok[0], "srcset")
    elif name == "ping":
        for tok in v.split():
            L.add(tok, "attr:ping")
    elif name == "content":
        m = _REFRESH_URL.search(v)
        h = _REFRESH_HEAD.match(v)
        if m or h:
            tail = v[m.end():] if m else v[h.end():]
            L.add(tail.strip().strip("\"'"), "meta-refresh")
        else:
            L.add(v, "attr:content", url_attr=False)
    elif name == "srcdoc":
        if depth < 3:
            old, L.prefix = L.prefix, L.prefix + "srcdoc>"
            _extract(v, L, depth + 1)
            L.prefix = old
    elif name.startswith("on"):
        _from_script(v, L, f"attr:{name}")
    else:
        L.add(v, f"attr:{name}", url_attr=name in _URL_ATTRS)


def _extract(pub: str, L: _Links, depth: int = 0) -> list[tuple[str, str]]:
    """把 pub 里所有写法的地址放进 L；返回 [(href 原值, 锚文本)]。"""
    anchors: list[tuple[str, str]] = []
    cur: list | None = None
    for kind, a, b, name, closing in _tokens(pub):
        if kind == "tag":
            tag = pub[a:b]
            if not closing:
                start = len(name) + 1
                for m in _ATTR_IN_TAG.finditer(tag, start):
                    val = next((g for g in m.groups()[1:] if g is not None), "")
                    _from_attr(m.group(1), val, L, depth)
            if name == "a":
                if cur is not None:
                    anchors.append((cur[0], html_text("".join(cur[1])).strip()))
                    cur = None
                if not closing:
                    hv = next((next((g for g in m.groups()[1:] if g is not None), "")
                               for m in _ATTR_IN_TAG.finditer(tag, 2) if m.group(1).lower() == "href"), None)
                    cur = [_html.unescape(hv), []] if hv is not None else None
        elif kind == "text" and cur is not None:
            cur[1].append(pub[a:b])
        elif kind == "raw":
            if name == "style":
                _from_css(pub[a:b], L, "css")
            else:
                _from_script(pub[a:b], L, "script")
    if cur is not None:
        anchors.append((cur[0], html_text("".join(cur[1])).strip()))
    # 全文兜底：注释里、被错切的标签里的链接属性，以及任何位置的 CSS url(…) 与 <https://…> 自动链接
    for m in _ATTR_CORE.finditer(pub):
        val = next((g for g in m.groups()[1:] if g is not None), "")
        _from_attr(m.group(1), val, L, depth)
    for m in _CSS_URL.finditer(pub):
        L.add(_html.unescape(next((g for g in m.groups() if g is not None), "")), "css")
    for m in _AUTOLINK.finditer(pub):
        L.add(m.group(1), "autolink")
    return anchors


def extract_links(pub_html: str) -> list[dict]:
    """返回 [{url, raw, via, anchor}]。url 是规整后的绝对地址（或伪协议原文），raw 是原写法。

    覆盖的写法（via）：
      attr:<名>    任意标签属性里的绝对地址（href/src/action/formaction/poster/data/xlink:href/
                   SVG 的 to/values 等；img/iframe/form/link/script/embed/object 的地址属性都在内），
                   双引号 / 单引号 / 无引号，含 HTML 实体编码；
      srcset       srcset / imagesrcset 里的每个候选地址；
      css          style 属性与 <style> 块里的 url(…)、@import "…"、image-set("…")，先解 CSS 转义与注释；
      meta-refresh <meta http-equiv="refresh" content="0;url=…">（任何 content 值里的刷新写法）；
      script       <script> 块与 on* 事件属性里的字符串字面量 / 纯文本 URL；
      srcdoc>…     iframe srcdoc 里嵌套的 HTML（递归抽取）；
      autolink     Markdown 自动链接 <https://…>；
      markdown     [文字](地址) 与 ![图](地址)；
      text         正文里的纯文本 URL（http(s):// 或 www.）。
    地址先按浏览器规则规整：协议相对 `//host`、`/\\host`、`\\\\host`、`\\/host`，
    以及 `https:host`、中间夹 tab/换行的写法，都按绝对地址处理。
    """
    L = _Links()
    anchors = _extract(pub_html, L)
    for href, text in anchors:
        c = canonical_url(href or "")
        key = c.strip().lower() if _SCHEME_BAD.match(c or "") else c
        e = L.index.get(key)
        if e is not None and not e["anchor"]:
            e["anchor"] = text
    txt = html_text(pub_html)
    for m in _MD.finditer(txt):
        L.add(m.group(1), "markdown")
    for m in _BARE.finditer(txt):
        u = m.group(0).rstrip(".,;:")
        c = canonical_url(u if "//" in u else "http://" + u)
        if c and host_of(c) and c not in L.index:        # 与属性里的地址相同则已计入，不重复报
            e = {"url": c, "raw": u, "via": "text", "anchor": ""}
            L.index[c] = e
            L.items.append(e)
    return L.items


# ─────────────────────────── 规则文本片段 ───────────────────────────
SHINGLE = 30


def rules_shingles(texts: Iterable[str], exclude_texts: Iterable[str] = (), k: int = SHINGLE) -> set[str]:
    """把规则/提示词文本切成 k 字连续片段。

    texts:         不应出现在公开输出里的文本（系统提示词、内部规程、围栏说明段…）；
    exclude_texts: 输出骨架模板等本来就会出现在公开区的文本（HTML 会先转纯文本），
                   与之共有的片段被扣掉，避免误报。
    """
    grams: set[str] = set()
    for t in texts:
        t = norm_text(t)
        grams |= {t[i:i + k] for i in range(0, max(0, len(t) - k + 1))}
    for s in exclude_texts:
        s = norm_text(html_text(s))
        grams -= {s[i:i + k] for i in range(0, max(0, len(s) - k + 1))}
    return grams


# ─────────────────────────── 私有特征 ───────────────────────────
CANARY = re.compile(r"CANARY[-_ ][\w一-鿿-]{2,}", re.I)
FENCE_LEAK = re.compile(r"UNTRUSTED[-_ ]?DATA|nonce\s*=\s*[0-9a-f]{8,}", re.I)
_HIDDEN_CH = re.compile("[​-‏⁠-⁤﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")
_HIDDEN_STYLE = re.compile(
    r"style\s*=\s*[\"'][^\"']*(?:font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d])"
    r"|color\s*:\s*transparent|visibility\s*:\s*hidden)", re.I)
# 「私有」的判据不能是「在私有区出现过」（私有区常会复述公开内容，同一句话本来就两边都有），
# 要是「**只**属于私有侧的东西」：私有句式，或私有原文的指纹。
# 默认句式是通用示例：「私有笔记：…」「内部记录：…」这类「标签 + 冒号/引号」。
# 换成你自己系统里私有内容渲染时的固定写法：private_label_patterns([...]) 或直接传正则。
DEFAULT_PRIVATE_LABELS: tuple[str, ...] = ("私有笔记", "私人笔记", "内部记录", "内部笔记",
                                           "private notes", "private note", "internal records", "internal record")


def private_label_patterns(labels: Iterable[str]) -> tuple[str, ...]:
    """把私有内容的固定标签（例如「私有笔记」）变成「标签 + 冒号/引号」句式正则，供 private_patterns 使用。"""
    alt = "|".join(sorted({re.escape(x) for x in labels if x}, key=len, reverse=True))
    return (rf"(?i:{alt})\s*[:：「]",) if alt else ()


DEFAULT_PRIVATE_PATTERNS: tuple[str, ...] = private_label_patterns(DEFAULT_PRIVATE_LABELS)


def private_fingerprints(texts: Iterable[str], min_len: int = 8, keep: int = 16) -> list[str]:
    """把私有原文（用户笔记、内部记录等）变成指纹：归一化后取前 keep 字；太短的丢掉。

    指纹只在内存里用来比对，不需要落盘。
    """
    out = []
    for t in texts:
        v = norm_text(t or "")
        if len(v) >= min_len:
            out.append(v[:keep])
    return out


# ─────────────────────────── 污点追踪 ───────────────────────────
_SENT = re.compile(r"[^。！？!?\n]+[。！？!?]?")
_CODEY = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+){1,}\b")
_QUOTED = re.compile(r"[“「『\"]([^”」』\"]{4,60})[”」』\"]")


def taint_tokens(source_items: Sequence[dict], fields: Sequence[str] = ("title", "summary")) -> list[tuple[str, str]]:
    """抓取层标记条目里，**指令所在句**要求写出的记号 → [(token, 条目标题)]。"""
    out = []
    for it in source_items:
        f = scan_item(it, fields)
        if not f:
            continue
        # 编码/不可见载体（base64、标签字符）的指令不在原文句子里，扫描器解码后的 span 才是指令本身
        for r in f["reasons"]:
            if r["family"] in ("encoded", "hidden", "comment") and r.get("span"):
                for t in set(_CODEY.findall(r["span"])) | set(_QUOTED.findall(r["span"])):
                    if len(t) >= 6:
                        out.append((t, (it.get("title") or "")[:40]))
        for fld in fields:
            raw = it.get(fld) or ""
            if not raw:
                continue
            spans = [r["span"] for r in f["reasons"] if r.get("field") == fld and r.get("span")]
            sents = _SENT.findall(raw)
            for i, s in enumerate(sents):
                ns = normalize(s)
                if not any(sp[:12] in ns for sp in spans):
                    continue
                window = " ".join(sents[i:i + 2])
                toks = set(_CODEY.findall(window)) | set(_QUOTED.findall(window))
                toks |= {m.group(0).rstrip(".,;:") for m in _BARE.finditer(window)}
                for t in toks:
                    if len(t) >= 6:
                        out.append((t, (it.get("title") or "")[:40]))
    return out


# ─────────────────────────── 主检查 ───────────────────────────
def check_html(html: str, *, source_items: Sequence[dict] = (), trusted_urls: Iterable[str] = (),
               allowed_domains: Iterable[str] | None = None, shingles: set[str] | None = None,
               private_texts: Sequence[str] | None = None,
               private_patterns: Sequence[str] = DEFAULT_PRIVATE_PATTERNS,
               strip_private: Callable[[str], str] = public_region) -> list[dict]:
    """返回发现列表 [{kind, detail}]。不读写任何文件。

    html:            即将发布的输出（HTML 或纯文本）；
    source_items:    本批喂给模型的外部条目（含 url / title / summary）；
    trusted_urls:    额外可信的完整 URL（例如历史跟踪中的条目）；
    allowed_domains: 已知良性注册域名（见 known_domains()）；None = 空白名单；
    shingles:        rules_shingles() 的结果；None / 空 = 不查规则片段；
    private_texts:   private_fingerprints() 的结果；
    private_patterns:私有句式正则（默认见 DEFAULT_PRIVATE_PATTERNS；可用 private_label_patterns() 生成）；
    strip_private:   从完整输出中取出「会被发布的部分」的函数（默认 public_region；
                     换标记用 make_public_region(start, end)）。发布端必须用同一个函数。
    """
    pub = strip_private(html)
    pub_txt = html_text(pub)
    raw_urls = {it.get("url") for it in source_items if it.get("url")} | set(trusted_urls or ())
    urls = raw_urls | {canonical_url(u) for u in raw_urls} - {""}
    allowed = set(allowed_domains or ())
    brands = _brands(allowed)
    allowed |= {reg_domain(host_of(u)) for u in urls}
    allowed -= {""}
    findings: list[dict] = []

    # ① 外链
    for L in extract_links(pub):
        u, raw = L["url"], L["raw"]
        shown = raw[:90] if raw == u else f"{raw[:60]}（按 {u[:60]} 解析）"
        if _SCHEME_BAD.match(u):
            findings.append({"kind": "link_scheme", "detail": f"[{L['via']}] 伪协议链接 {raw[:60]}"})
            continue
        h = host_of(u)
        rd = reg_domain(h)
        if _IP.match(h or ""):
            findings.append({"kind": "link_ip", "detail": f"[{L['via']}] 裸 IP 链接 {shown}"})
            continue
        if u not in urls and raw not in urls and rd not in allowed:
            brand = next((b for b in brands if b in h), "")
            tail = f"（主机名含白名单品牌「{brand}」，疑似仿冒）" if brand else ""
            findings.append({"kind": "link_unauthorized",
                             "detail": f"[{L['via']}] {shown} 不在本批原料、域名 {rd} 不在白名单{tail}"})
        a = L.get("anchor") or ""
        am = _BARE.search(a)
        if am and reg_domain(host_of(am.group(0))) not in ("", rd):
            findings.append({"kind": "link_mismatch",
                             "detail": f"锚文本显示 {reg_domain(host_of(am.group(0)))}，实际指向 {rd}"})

    # ② 规则文本片段
    if shingles:
        p = norm_text(pub_txt)
        hit = next((p[i:i + SHINGLE] for i in range(0, max(0, len(p) - SHINGLE + 1))
                    if p[i:i + SHINGLE] in shingles), "")
        if hit:
            findings.append({"kind": "rules_leak", "detail": f"公开区含规则/提示词原文片段「{hit[:30]}…」"})

    # ③④⑤ 金丝雀 / 围栏 / 私有内容
    for m in CANARY.finditer(pub_txt):
        findings.append({"kind": "canary", "detail": f"公开区出现金丝雀 {m.group(0)[:40]}"})
        break
    m = FENCE_LEAK.search(pub_txt)
    if m:
        findings.append({"kind": "fence_leak", "detail": f"公开区出现围栏分隔符/nonce「{m.group(0)[:40]}」"})
    for pat in private_patterns:
        m = re.search(pat, pub_txt)
        if m:
            findings.append({"kind": "private_leak", "detail": f"公开区出现私有句式「{m.group(0)[:40]}」"})
            break
    pn = norm_text(pub_txt)
    for t in (private_texts or []):
        if t in pn:
            findings.append({"kind": "private_leak", "detail": f"公开区出现私有原文指纹「{t}」"})
            break

    # ⑥ 隐藏文字
    hc = _HIDDEN_CH.findall(pub_txt)
    if hc:
        findings.append({"kind": "hidden_chars", "detail": f"公开区含 {len(hc)} 个零宽/不可见字符"})
    hs = _HIDDEN_STYLE.search(pub)
    if hs:
        findings.append({"kind": "hidden_style", "detail": f"公开区含内联隐藏样式「{hs.group(0)[:50]}」"})

    # ⑥ 污点追踪
    seen = set()
    for tok, src_title in taint_tokens(source_items):
        if tok in pub_txt and tok not in seen:
            seen.add(tok)
            findings.append({"kind": "taint",
                             "detail": f"被标记条目「{src_title}」里指令要求写出的「{tok[:40]}」出现在公开区"})
    return findings


# ─────────────────────────── 告警 / 拦截 ───────────────────────────
def enforce_from_env() -> bool:
    return os.environ.get("INJECTION_GUARD_ENFORCE", "") == "1"


@dataclass
class Report:
    findings: list[dict] = field(default_factory=list)
    enforce: bool = False

    @property
    def blocked(self) -> bool:
        """只有 enforce=True 且有发现时才为 True。默认模式永远不拦截。"""
        return self.enforce and bool(self.findings)

    def lines(self, limit: int = 12) -> list[str]:
        mark = "BLOCK" if self.enforce else "INFO"
        if not self.findings:
            return ["INFO 输出侧：未发现注入生效痕迹（外链/规则片段/金丝雀/围栏/私有内容/隐藏文字/污点）"]
        out = [f"{mark} [{x['kind']}] {x['detail']}" for x in self.findings[:limit]]
        if len(self.findings) > limit:
            out.append(f"INFO 另有 {len(self.findings) - limit} 条同类发现未列出")
        if not self.enforce:
            out.append("INFO 以上仅告警（默认不拦截）；enforce=True 或 INJECTION_GUARD_ENFORCE=1 可改为拦截")
        return out


def check_output(html: str, *, enforce: bool | None = None, **kwargs) -> Report:
    """check_html 的包装：返回 Report。enforce 为 None 时读环境变量 INJECTION_GUARD_ENFORCE。"""
    return Report(findings=check_html(html, **kwargs),
                  enforce=enforce_from_env() if enforce is None else enforce)
