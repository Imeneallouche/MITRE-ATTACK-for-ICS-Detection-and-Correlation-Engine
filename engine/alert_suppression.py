"""Optional policy hook: suppress alerts when rules match.

Rules are supplied via configuration (for example ``alert_suppression_rules``
in YAML) or by merging policy at runtime. The default repository config ships
with **no** rules so the engine does not encode site-specific benign patterns;
a future reinforcement-learning or policy service can emit rules dynamically
without changing core detection logic.

Each rule may filter by datacomponent IDs, log sources, message substrings,
and ``raw_field_equals`` (AND) against the Elasticsearch document
(``raw_source``).
"""
from __future__ import annotations

from typing import Any, Dict, List


def _get_path(obj: Any, path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def should_suppress_alert(
    event: Any,
    datacomponent_id: str,
    rules: List[Dict[str, Any]],
) -> bool:
    if not rules:
        return False

    msg = (getattr(event, "log_message", "") or "").lower()
    src = (getattr(event, "log_source_normalized", "") or "").lower()
    raw = getattr(event, "raw_source", None) or {}
    if not isinstance(raw, dict):
        raw = {}

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        dcs = rule.get("datacomponents") or []
        if dcs and datacomponent_id not in dcs:
            continue
        sources = [str(x).lower() for x in (rule.get("log_sources") or [])]
        if sources and src not in sources:
            continue

        subs = [str(x).lower() for x in (rule.get("message_substrings") or [])]
        if subs:
            mode = str(rule.get("message_match", "any")).lower()
            if mode == "all":
                if not all(s in msg for s in subs):
                    continue
            else:
                if not any(s in msg for s in subs):
                    continue

        raw_conds = rule.get("raw_field_equals") or []
        raw_ok = True
        for cond in raw_conds:
            if not isinstance(cond, dict):
                continue
            path = str(cond.get("path", ""))
            expect = cond.get("value")
            actual = _get_path(raw, path)
            if actual is None and path in raw:
                actual = raw.get(path)
            if str(actual) != str(expect):
                raw_ok = False
                break
        if not raw_ok:
            continue

        return True

    return False
