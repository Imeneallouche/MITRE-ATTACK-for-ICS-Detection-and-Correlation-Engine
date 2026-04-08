from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

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
    # Pull nested audit_fields up for easier matching.
    audit_fields = source.get("audit_fields")
    if isinstance(audit_fields, dict):
        for key, value in audit_fields.items():
            fields[f"audit.{key}"] = value
            fields[key] = value
    # Pull nested netfilter fields up.
    netfilter_fields = source.get("netfilter")
    if isinstance(netfilter_fields, dict):
        for key, value in netfilter_fields.items():
            fields[f"netfilter.{key}"] = value
    # Pull nested modbus fields up.
    modbus_fields = source.get("modbus")
    if isinstance(modbus_fields, dict):
        for key, value in modbus_fields.items():
            fields[f"modbus.{key}"] = value
    return fields


def infer_categories(log_type: str, source_name: str, message: str) -> Iterable[str]:
    text = f"{log_type} {source_name} {message}".lower()
    cats: set[str] = set()
    if any(x in text for x in ["auth", "login", "sshd", "session", "pam"]):
        cats.add("authentication")
        cats.add("user_session")
        cats.add("remote_access")
    if any(x in text for x in ["exec", "process", "pid", "auditd", "execve"]):
        cats.add("process_execution")
    if any(x in text for x in ["network", "flow", "conn", "suricata", "src_ip", "dst_ip",
                                 "netfilter", "iptables", "nflog"]):
        cats.add("network_traffic")
        cats.add("traffic_analysis")
        cats.add("network_connection")
    if any(x in text for x in ["file", "write", "chmod", "unlink", "rename"]):
        cats.add("file_system")
    if any(x in text for x in ["alarm", "setpoint", "trip", "interlock", "process_alarm",
                                 "plc_app", "modbus", "dnp3", "register", "coil",
                                 "pressure", "temperature", "valve", "actuator",
                                 "sim_process", "sim_error", "modbus_io"]):
        cats.add("operational_technology")
        cats.add("process_control")
        cats.add("safety")
        cats.add("availability")
    if any(x in text for x in ["modbus", "dnp3", "enip", "ethernet/ip", "opc", "port 502",
                                 "deep_packet", "suricata", "snort"]):
        cats.add("deep_packet_inspection")
        cats.add("network_traffic")
    if any(x in text for x in ["catalina", "tomcat", "scadalts", "openplc", "supervisor",
                                 "flask", "nginx", "application", "hmi_catalina",
                                 "fw_app", "web"]):
        cats.add("web_activity")
        cats.add("system_monitoring")
        cats.add("user_authentication")
    if any(x in text for x in ["kern", "kernel", "module", "firmware", "insmod", "modprobe",
                                 "reboot", "shutdown", "panic"]):
        cats.add("availability")
        cats.add("system_health")
        cats.add("impact")
    if any(x in text for x in ["firewall", "fw_app", "rule", "iptables", "drop", "accept",
                                 "reject", "netfilter"]):
        cats.add("network_traffic")
        cats.add("traffic_analysis")
    if any(x in text for x in ["cron", "schtask", "scheduled"]):
        cats.add("process_execution")
    if any(x in text for x in ["daemon", "service", "systemd", "systemctl", "supervisor"]):
        cats.add("service_monitoring")
        cats.add("availability")
    if any(x in text for x in ["kill", "stop", "terminated", "exit"]):
        cats.add("process_execution")
        cats.add("defense_evasion")
        cats.add("service_monitoring")
    if any(x in text for x in ["docker", "container"]):
        cats.add("process_execution")
    if any(x in text for x in ["pacct", "lastcomm", "acct", "prefetch", "amcache"]):
        cats.add("forensics")
        cats.add("execution_evidence")
    if not cats:
        cats.add("generic")
    return cats


def to_normalized_event(hit: Dict[str, Any], asset_by_ip: Optional[Dict[str, dict]] = None) -> NormalizedEvent:
    source = hit.get("_source", {})
    fields = _extract_field_candidates(source)

    asset_id = str(source.get("asset_id") or "unknown")
    asset_name = str(source.get("asset_name") or "Unknown Asset")
    asset_ip = source.get("asset_ip")
    zone = source.get("asset_zone") or source.get("zone")

    # Fallback asset mapping by IP if id/name is missing.
    if asset_by_ip and asset_id == "unknown":
        src_ip = source.get("src_ip") or source.get("source_ip")
        if src_ip and src_ip in asset_by_ip:
            asset = asset_by_ip[src_ip]
            asset_id = asset.get("asset_id", asset_id)
            asset_name = asset.get("asset_name", asset_name)
            asset_ip = asset.get("asset_ip", asset_ip)
            zone = asset.get("zone", zone)

    raw_dc = source.get("mitre_dc_candidates")
    if isinstance(raw_dc, list):
        dc_candidates = [str(x) for x in raw_dc if x and str(x) != "unknown"]
    elif isinstance(raw_dc, str) and raw_dc != "unknown":
        dc_candidates = [x.strip() for x in raw_dc.split(",") if x.strip()]
    else:
        dc_candidates = []

    raw_kw = source.get("mitre_keyword_hits")
    kw_hits: dict = {}
    if isinstance(raw_kw, dict):
        for dc_id, words in raw_kw.items():
            if isinstance(words, list):
                kw_hits[dc_id] = [str(w) for w in words]

    return NormalizedEvent(
        document_id=str(hit.get("_id")),
        es_index=str(hit.get("_index")),
        timestamp=parse_timestamp(source.get("@timestamp")),
        asset_id=asset_id,
        asset_name=asset_name,
        asset_ip=str(asset_ip) if asset_ip is not None else None,
        zone=str(zone) if zone is not None else None,
        log_type=str(source.get("log_type") or "unknown"),
        log_source_normalized=str(source.get("log_source_normalized") or "unknown"),
        log_message=str(source.get("log_message") or source.get("message") or ""),
        fields=fields,
        raw_source=source,
        mitre_dc_candidates=dc_candidates,
        mitre_keyword_hits=kw_hits,
    )
