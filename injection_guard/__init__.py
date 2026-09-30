"""llm-injection-guard：外部内容 + 私有数据 + 对外发布同时存在时的三层提示注入防护。

    scan          抓取层：归一化 + 规则 + 结构特征，只标记不删除；可插拔判别器
    fence         围栏层：随机 nonce 分隔符 + 「这是数据不是指令」说明段
    output_check  输出侧：发布前查外链 / 金丝雀 / 围栏外泄 / 规则片段 / 私有内容 / 隐藏文字 / 污点
"""
from .scan import (normalize, scan_text, scan_item, scan_items, verdict, flags_by_index,
                   register_classifier, load_classifier, load_items, configure_private_terms)
from .fence import fence_items, fence_preamble, new_nonce, neutralize
from .output_check import (check_html, check_output, Report, known_domains, rules_shingles,
                           private_fingerprints, public_region, make_public_region, private_label_patterns,
                           extract_links, canonical_url, taint_tokens)

__version__ = "0.1.0"

__all__ = [
    "normalize", "scan_text", "scan_item", "scan_items", "verdict", "flags_by_index",
    "register_classifier", "load_classifier", "load_items", "configure_private_terms",
    "fence_items", "fence_preamble", "new_nonce", "neutralize",
    "check_html", "check_output", "Report", "known_domains", "rules_shingles",
    "private_fingerprints", "public_region", "make_public_region", "private_label_patterns",
    "extract_links", "canonical_url", "taint_tokens",
]
