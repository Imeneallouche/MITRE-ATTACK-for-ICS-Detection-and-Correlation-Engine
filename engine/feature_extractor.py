"""Normalize raw Elasticsearch hits into structured NormalizedEvent objects.

All shaping rules — field aliases, nested promotion, embedding key fields,
asset-IP candidate fields, and category inference — are configuration
driven. The engine ships no hard-coded environment-specific behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from dateutil import parser as dtparser

from .models import NormalizedEvent


@dataclass
class CategoryRule:
    categories: List[str]
    text_substrings: List[str] = field(default_factory=list)
    source_substrings: List[str] = field(default_factory=list)
    match: str = "any"  # "any" | "all"


@dataclass
class NormalizationRules:
    """Container for all configuration-driven normalization rules."""

    field_aliases: Dict[str, str] = field(default_factory=dict)
    # ECS / vendor field -> additional keys that mirror the same value so
    # MITRE catalog ``searchable_indexes.fields`` (e.g. SourceIp) overlap
    # with common log shapes (src_ip) without per-DC code.
    field_name_aliases: Dict[str, List[str]] = field(default_factory=dict)
    promoted_field_roots: List[str] = field(default_factory=list)
    embedding_key_fields: List[str] = field(default_factory=list)
    asset_ip_field_candidates: List[str] = field(default_factory=list)
    category_rules: List[CategoryRule] = field(default_factory=list)
    default_categories: List[str] = field(default_factory=list)
    # ``message_primary``: semantic encoding uses observed log source + *original* body only
    # (no appended key=value telemetry), aligning with DC description + channel text.
    # ``full``: legacy behaviour — append ``embedding_key_fields`` for extra context.
    embedding_text_mode: str = "message_primary"

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "NormalizationRules":
        cfg = cfg or {}

        def _str_list(value: Any) -> List[str]:
            return [str(x) for x in value] if isinstance(value, list) else []

        aliases_raw = cfg.get("field_aliases") or {}
        aliases = {str(k).lower(): str(v) for k, v in aliases_raw.items()} \
            if isinstance(aliases_raw, dict) else {}

        rules: List[CategoryRule] = []
        for entry in cfg.get("category_rules") or []:
            if not isinstance(entry, dict):
                continue
            cats = _str_list(entry.get("categories"))
            if not cats:
                continue
            rules.append(CategoryRule(
                categories=cats,
                text_substrings=[s.lower() for s in _str_list(entry.get("text_substrings"))],
                source_substrings=[s.lower() for s in _str_list(entry.get("source_substrings"))],
                match=str(entry.get("match", "any")).lower(),
            ))

        fn_aliases: Dict[str, List[str]] = {}
        raw_fn = cfg.get("field_name_aliases")
        if isinstance(raw_fn, dict):
            for k, v in raw_fn.items():
                key = str(k)
                if isinstance(v, list):
                    fn_aliases[key] = [str(x) for x in v if x]
                elif v:
                    fn_aliases[key] = [str(v)]

        mode = str(cfg.get("embedding_text_mode", "message_primary")).strip().lower()
        if mode not in ("message_primary", "full"):
            mode = "message_primary"

        return cls(
            field_aliases=aliases,
            field_name_aliases=fn_aliases,
            promoted_field_roots=_str_list(cfg.get("promoted_field_roots")),
            embedding_key_fields=_str_list(cfg.get("embedding_key_fields")),
            asset_ip_field_candidates=_str_list(cfg.get("asset_ip_field_candidates")),
            category_rules=rules,
            default_categories=_str_list(cfg.get("default_categories")),
            embedding_text_mode=mode,
        )


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


class EventNormalizer:
    """Convert raw ES hits into NormalizedEvent objects using config rules.

    The normalizer is stateless beyond its rules; one instance is shared
    across the engine runtime.
    """

    def __init__(
        self,
        rules: Optional[NormalizationRules] = None,
        asset_by_ip: Optional[Dict[str, dict]] = None,
    ) -> None:
        self.rules = rules or NormalizationRules()
        self.asset_by_ip = asset_by_ip or {}

    def normalize(self, hit: Dict[str, Any]) -> NormalizedEvent:
        source = hit.get("_source", {}) or {}
        fields = self._extract_field_candidates(source)

        asset_id, asset_name, asset_ip, zone, is_ics, asset_role = self._resolve_asset(
            source, fields,
        )

        dc_candidates = self._extract_dc_candidates(source.get("mitre_dc_candidates"))
        kw_hits = self._extract_keyword_hits(source.get("mitre_keyword_hits"))

        log_type = str(source.get("log_type") or "unknown")
        log_source = str(source.get("log_source_normalized") or "unknown")
        original_log_message = str(source.get("log_message") or source.get("message") or "").strip()
        log_message = original_log_message
        if not log_message:
            log_message = self._synthesize_fallback_message(source, fields)

        categories = sorted(self._infer_categories(log_type, log_source, log_message))
        emb_text = self._build_embedding_text(
            original_body=original_log_message,
            log_source=log_source,
            fields=fields,
        )

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
            original_log_message=original_log_message,
            is_ics_asset=is_ics,
            asset_role=asset_role,
            categories=categories,
            mitre_dc_candidates=dc_candidates,
            mitre_keyword_hits=kw_hits,
            embedding_text=emb_text,
        )

    # ── Field shaping ──────────────────────────────────────────────────────

    def _extract_field_candidates(self, source: Dict[str, Any]) -> Dict[str, Any]:
        fields = dict(source)
        aliases = self.rules.field_aliases
        if aliases:
            for key, value in list(source.items()):
                low = key.lower()
                if low in aliases:
                    fields[aliases[low]] = value

        for nested_key in self.rules.promoted_field_roots:
            nested = source.get(nested_key)
            if isinstance(nested, dict):
                for k, v in nested.items():
                    fields[f"{nested_key}.{k}"] = v
                    fields[k] = v

        self._apply_field_name_aliases(fields)
        return fields

    def _apply_field_name_aliases(self, fields: Dict[str, Any]) -> None:
        """Duplicate values under MITRE-style names (and configured aliases)."""
        aliases = self.rules.field_name_aliases
        if not aliases:
            return
        # Snapshot keys so mirroring does not recurse infinitely.
        for key, val in list(fields.items()):
            if val is None or val == "":
                continue
            targets = aliases.get(key)
            if targets is None:
                targets = aliases.get(key.lower())
            if not targets:
                continue
            for alt in targets:
                if alt not in fields or fields[alt] in (None, ""):
                    fields[alt] = val

    def _synthesize_fallback_message(
        self,
        source: Dict[str, Any],
        fields: Dict[str, Any],
    ) -> str:
        """When ``message`` / ``log_message`` is empty (common for flow-only IDS rows)."""
        parts: List[str] = []
        lt = str(source.get("log_type") or "").strip()
        if lt:
            parts.append(f"log_type={lt}")
        ls = str(source.get("log_source_normalized") or "").strip()
        if ls:
            parts.append(f"log_source_normalized={ls}")
        for key in sorted(self.rules.embedding_key_fields):
            val = fields.get(key)
            if val is not None and str(val).strip():
                parts.append(f"{key}={val}")
        return " ".join(parts).strip()

    def _build_embedding_text(
        self,
        *,
        original_body: str,
        log_source: str,
        fields: Dict[str, Any],
    ) -> str:
        """Text encoded for the embedding model vs. DC description + channel embeddings.

        ``message_primary`` uses only the catalog-style log source tag and the *original*
        indexed message body so similarity reflects narrative content, not derived metadata.
        """
        body = (original_body or "").strip()
        parts: List[str] = [f"[{log_source}]"]
        if body:
            parts.append(body)
        if self.rules.embedding_text_mode == "full":
            for key in sorted(self.rules.embedding_key_fields):
                val = fields.get(key)
                if val is not None and str(val).strip():
                    parts.append(f"{key}={val}")
        text = " ".join(parts)
        if len(text) > 1024:
            text = text[:1024]
        return text

    # ── Asset resolution ───────────────────────────────────────────────────

    def _resolve_asset(
        self,
        source: Dict[str, Any],
        fields: Dict[str, Any],
    ):
        asset_id = str(source.get("asset_id") or "unknown")
        asset_name = str(source.get("asset_name") or "Unknown Asset")
        asset_ip = source.get("asset_ip")
        zone = source.get("asset_zone") or source.get("zone")
        is_ics = False
        asset_role = ""

        candidates: Iterable[str] = self.rules.asset_ip_field_candidates
        if self.asset_by_ip and asset_id == "unknown":
            for ip_key in candidates:
                ip_val = source.get(ip_key) or fields.get(ip_key)
                if ip_val and ip_val in self.asset_by_ip:
                    asset = self.asset_by_ip[ip_val]
                    asset_id = asset.get("asset_id", asset_id)
                    asset_name = asset.get("asset_name", asset_name)
                    asset_ip = asset.get("asset_ip", asset_ip)
                    zone = asset.get("zone", zone)
                    is_ics = bool(asset.get("is_ics_asset"))
                    asset_role = asset.get("role", "")
                    break

        if self.asset_by_ip and asset_ip and asset_ip in self.asset_by_ip:
            a = self.asset_by_ip[asset_ip]
            is_ics = bool(a.get("is_ics_asset"))
            asset_role = a.get("role", asset_role)

        return asset_id, asset_name, asset_ip, zone, is_ics, asset_role

    # ── Mitre enrichment passthrough ───────────────────────────────────────

    @staticmethod
    def _extract_dc_candidates(raw: Any) -> List[str]:
        if isinstance(raw, list):
            return [str(x) for x in raw if x and str(x) != "unknown"]
        if isinstance(raw, str) and raw and raw != "unknown":
            return [x.strip() for x in raw.split(",") if x.strip()]
        return []

    @staticmethod
    def _extract_keyword_hits(raw: Any) -> Dict[str, list]:
        out: Dict[str, list] = {}
        if isinstance(raw, dict):
            for dc_id, words in raw.items():
                if isinstance(words, list):
                    out[str(dc_id)] = [str(w) for w in words]
        return out

    # ── Category inference ─────────────────────────────────────────────────

    def _infer_categories(
        self, log_type: str, source_name: str, message: str,
    ) -> Set[str]:
        cats: Set[str] = set()
        text = f"{log_type} {source_name} {message}".lower()
        src_lower = source_name.lower()

        for rule in self.rules.category_rules:
            if rule.source_substrings and not any(
                s in src_lower for s in rule.source_substrings
            ):
                continue
            if rule.text_substrings:
                if rule.match == "all":
                    matched = all(s in text for s in rule.text_substrings)
                else:
                    matched = any(s in text for s in rule.text_substrings)
                if not matched:
                    continue
            cats.update(rule.categories)

        if not cats:
            cats.update(self.rules.default_categories)
        return cats
