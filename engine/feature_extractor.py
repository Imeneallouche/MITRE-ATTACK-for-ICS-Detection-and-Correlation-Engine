"""Normalize raw Elasticsearch hits into structured NormalizedEvent objects.

Handles field alias resolution, nested field promotion, timestamp parsing,
asset mapping, Logstash enrichment extraction, and category inference.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Set

from dateutil import parser as dtparser

from .models import NormalizedEvent


FIELD_ALIASES = {
    "source_ip": "src_ip",
    "sourceip": "src_ip",
    "srcip": "src_ip",
    "destination_ip": "dst_ip",
    "destinationip": "dst_ip",
    "dest_ip": "dst_ip",
    "destip": "dst_ip",
    "user": "auth_user",
    "username": "auth_user",
    "processname": "process_name",
    "netfilter.src_ip": "src_ip",
    "netfilter.dest_ip": "dst_ip",
    "netfilter.src_port": "src_port",
    "netfilter.dest_port": "dest_port",
    "modbus.function_code": "modbus_function_code",
    "modbus.exception_code": "modbus_exception_code",
}


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str) and value:
        parsed = dtparser.parse(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return datetime.now(tz=timezone.utc)


def _extract_field_candidates(source: Dict[str, Any]) -> Dict[str, Any]:
    fields = dict(source)
    for key, value in list(source.items()):
        low = key.lower()
        if low in FIELD_ALIASES:
            fields[FIELD_ALIASES[low]] = value

    for nested_key in ("audit_fields", "netfilter", "modbus", "ics"):
        nested = source.get(nested_key)
        if isinstance(nested, dict):
            for k, v in nested.items():
                fields[f"{nested_key}.{k}"] = v
                fields[k] = v
    return fields


def infer_categories(log_type: str, source_name: str, message: str) -> Set[str]:
    text = f"{log_type} {source_name} {message}".lower()
    cats: Set[str] = set()

    if any(x in text for x in ["auth", "login", "sshd", "session", "pam"]):
        cats.update({"authentication", "user_session", "remote_access"})
    if any(x in text for x in ["exec", "process", "pid", "auditd", "execve"]):
        cats.add("process_execution")
    if any(x in text for x in [
        "network", "flow", "conn", "suricata", "src_ip", "dst_ip",
        "netfilter", "iptables", "nflog",
    ]):
        cats.update({"network_traffic", "traffic_analysis", "network_connection"})
    if any(x in text for x in ["file", "write", "chmod", "unlink", "rename"]):
        cats.add("file_system")
    if any(x in text for x in [
        "alarm", "setpoint", "trip", "interlock", "process_alarm",
        "plc_app", "modbus", "dnp3", "register", "coil",
        "pressure", "temperature", "valve", "actuator",
        "sim_process", "sim_error", "modbus_io",
    ]):
        cats.update({"operational_technology", "process_control", "safety", "availability"})
    if any(x in text for x in [
        "modbus", "dnp3", "enip", "ethernet/ip", "opc", "port 502",
        "deep_packet", "suricata", "snort",
    ]):
        cats.update({"deep_packet_inspection", "network_traffic"})
    if any(x in text for x in [
        "catalina", "tomcat", "scadalts", "openplc", "supervisor",
        "flask", "nginx", "application", "hmi_catalina", "fw_app", "web",
    ]):
        cats.update({"web_activity", "system_monitoring", "user_authentication"})
    if any(x in text for x in [
        "kern", "kernel", "module", "firmware", "insmod", "modprobe",
        "reboot", "shutdown", "panic",
    ]):
        cats.update({"availability", "system_health", "impact"})
    if any(x in text for x in [
        "firewall", "fw_app", "rule", "iptables", "drop", "accept",
        "reject", "netfilter",
    ]):
        cats.update({"network_traffic", "traffic_analysis"})
    if any(x in text for x in ["cron", "schtask", "scheduled"]):
        cats.add("process_execution")
    if any(x in text for x in ["daemon", "service", "systemd", "systemctl", "supervisor"]):
        cats.update({"service_monitoring", "availability"})
    if any(x in text for x in ["kill", "stop", "terminated", "exit"]):
        cats.update({"process_execution", "defense_evasion", "service_monitoring"})
    if any(x in text for x in ["docker", "container"]):
        cats.add("process_execution")
    if any(x in text for x in ["pacct", "lastcomm", "acct", "prefetch", "amcache"]):
        cats.update({"forensics", "execution_evidence"})
    if any(x in text for x in ["anomaly", "deviation", "unexpected", "unusual"]):
        cats.add("anomaly_detection")
    if any(x in text for x in ["command", "cmd", "script", "bash", "python", "sh"]):
        cats.add("process_execution")
    if any(x in text for x in ["privilege", "sudo", "su ", "root"]):
        cats.add("privilege_escalation")
    if any(x in text for x in ["exfil", "upload", "transfer", "staging"]):
        cats.add("exfiltration")

    if not cats:
        cats.add("generic")
    return cats


def to_normalized_event(
    hit: Dict[str, Any],
    asset_by_ip: Optional[Dict[str, dict]] = None,
) -> NormalizedEvent:
    source = hit.get("_source", {})
    fields = _extract_field_candidates(source)

    asset_id = str(source.get("asset_id") or "unknown")
    asset_name = str(source.get("asset_name") or "Unknown Asset")
    asset_ip = source.get("asset_ip")
    zone = source.get("asset_zone") or source.get("zone")
    is_ics = False
    asset_role = ""

    if asset_by_ip and asset_id == "unknown":
        for ip_key in ("src_ip", "source_ip", "dst_ip", "destination_ip"):
            ip_val = source.get(ip_key) or fields.get(ip_key)
            if ip_val and ip_val in asset_by_ip:
                asset = asset_by_ip[ip_val]
                asset_id = asset.get("asset_id", asset_id)
                asset_name = asset.get("asset_name", asset_name)
                asset_ip = asset.get("asset_ip", asset_ip)
                zone = asset.get("zone", zone)
                is_ics = bool(asset.get("is_ics_asset"))
                asset_role = asset.get("role", "")
                break

    if asset_by_ip and asset_ip and asset_ip in asset_by_ip:
        a = asset_by_ip[asset_ip]
        is_ics = bool(a.get("is_ics_asset"))
        asset_role = a.get("role", asset_role)

    raw_dc = source.get("mitre_dc_candidates")
    if isinstance(raw_dc, list):
        dc_candidates = [str(x) for x in raw_dc if x and str(x) != "unknown"]
    elif isinstance(raw_dc, str) and raw_dc != "unknown":
        dc_candidates = [x.strip() for x in raw_dc.split(",") if x.strip()]
    else:
        dc_candidates = []

    raw_kw = source.get("mitre_keyword_hits")
    kw_hits: Dict[str, list] = {}
    if isinstance(raw_kw, dict):
        for dc_id, words in raw_kw.items():
            if isinstance(words, list):
                kw_hits[dc_id] = [str(w) for w in words]

    log_type = str(source.get("log_type") or "unknown")
    log_source = str(source.get("log_source_normalized") or "unknown")
    log_message = str(source.get("log_message") or source.get("message") or "")
    categories = sorted(infer_categories(log_type, log_source, log_message))

    return NormalizedEvent(
        document_id=str(hit.get("_id")),
        es_index=str(hit.get("_index")),
        timestamp=parse_timestamp(source.get("@timestamp")),
        asset_id=asset_id,
        asset_name=asset_name,
        asset_ip=str(asset_ip) if asset_ip else None,
        zone=str(zone) if zone else None,
        log_type=log_type,
        log_source_normalized=log_source,
        log_message=log_message,
        fields=fields,
        raw_source=source,
        is_ics_asset=is_ics,
        asset_role=asset_role,
        categories=categories,
        mitre_dc_candidates=dc_candidates,
        mitre_keyword_hits=kw_hits,
    )
