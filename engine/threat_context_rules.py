"""Configurable threat-context score adjustments.

All discriminators (log types, field names, values, ports, asset roles, datacomponent
IDs, boost magnitudes) are supplied via ``detection.yml`` under ``threat_context``.
This module contains no environment-specific literals.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .models import NormalizedEvent


def _field(raw: Dict[str, Any], fields: Dict[str, Any], key: str) -> Any:
    v = fields.get(key)
    if v is None or v == "":
        v = raw.get(key)
    return v


def _ips_for_roles(assets_by_ip: Dict[str, dict], roles: Set[str]) -> Set[str]:
    if not roles:
        return set()
    out: Set[str] = set()
    for ip, a in assets_by_ip.items():
        r = str(a.get("role", "")).lower()
        if r in roles:
            out.add(str(ip))
    return out


def _dest_ip_allowed(dest_s: str, rule: Dict[str, Any], assets_by_ip: Dict[str, dict]) -> bool:
    roles_raw = rule.get("destination_asset_roles")
    if not roles_raw:
        return True
    roles = {str(x).lower() for x in roles_raw}
    return dest_s in _ips_for_roles(assets_by_ip, roles)


def _port_allowed(dest_port: int, rule: Dict[str, Any]) -> bool:
    ports = rule.get("destination_ports")
    if ports is None:
        return True
    if not ports:
        return True
    try:
        want = [int(x) for x in ports]
    except (TypeError, ValueError):
        return False
    return (not dest_port) or (dest_port in want)


def _field_rules_match(event: NormalizedEvent, rule: Dict[str, Any]) -> bool:
    raw = event.raw_source or {}
    fields = event.fields or {}
    for fr in rule.get("match_fields") or []:
        if not isinstance(fr, dict):
            continue
        name = fr.get("name") or fr.get("field")
        if not name:
            continue
        want = fr.get("values") or fr.get("value")
        if want is None:
            continue
        if not isinstance(want, list):
            want = [want]
        got = _field(raw, fields, str(name))
        if str(got).lower() not in {str(v).lower() for v in want}:
            return False
    return True


def _log_type_match(event: NormalizedEvent, rule: Dict[str, Any]) -> bool:
    want = rule.get("match_log_type")
    if not want:
        return True
    return str(event.log_type).lower() == str(want).lower()


def _datacomponent_match(datacomponent_id: str, rule: Dict[str, Any]) -> bool:
    allowed = rule.get("match_datacomponent_ids")
    if not allowed:
        return True
    if not isinstance(allowed, list):
        return True
    return datacomponent_id in set(str(x) for x in allowed)


def _eval_boost_when(
    when: Optional[Dict[str, Any]],
    src_s: str,
    assets_by_ip: Dict[str, dict],
) -> bool:
    if not when:
        return True
    inv = when.get("source_ip_in_asset_inventory")
    if inv is True and src_s not in assets_by_ip:
        return False
    if inv is False and src_s in assets_by_ip:
        return False
    pred = when.get("source_asset")
    if isinstance(pred, dict) and src_s in assets_by_ip:
        a = assets_by_ip[src_s]
        for k, v in pred.items():
            if a.get(k) != v:
                return False
    return True


def max_score_boost_for_rules(
    event: NormalizedEvent,
    datacomponent_id: str,
    rules: List[Dict[str, Any]],
    assets_by_ip: Dict[str, dict],
) -> float:
    """Return the maximum additive score boost from all matching rules."""
    best = 0.0
    raw = event.raw_source or {}
    fields = event.fields or {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not _datacomponent_match(datacomponent_id, rule):
            continue
        if not _log_type_match(event, rule):
            continue
        if not _field_rules_match(event, rule):
            continue

        dest_s = str(_field(raw, fields, "dest_ip") or "")
        if not _dest_ip_allowed(dest_s, rule, assets_by_ip):
            continue

        dest_port_raw = _field(raw, fields, "dest_port")
        try:
            dp = (
                int(dest_port_raw)
                if dest_port_raw is not None and str(dest_port_raw).strip() != ""
                else 0
            )
        except (TypeError, ValueError):
            dp = 0
        if not _port_allowed(dp, rule):
            continue

        src_s = str(_field(raw, fields, "src_ip") or "")

        for boost in rule.get("boosts") or []:
            if not isinstance(boost, dict):
                continue
            add = float(boost.get("add", 0.0))
            when = boost.get("when")
            if not isinstance(when, dict):
                when = {}
            if _eval_boost_when(when, src_s, assets_by_ip):
                best = max(best, add)

    return best
