"""Load DataComponent profiles from JSON and build embedding text.

Each DataComponent JSON has a ``log_sources`` array with Name/Channel
entries.  The Channel strings contain rich natural-language descriptions of
what log events the DC detects.  We concatenate the DC description with
every non-trivial Channel string to produce a single embedding text that
captures the full detection semantics.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

from .models import DataComponentProfile, LogSourceEntry


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


_SKIP_CHANNELS = {"none", "n/a", "", "null"}


def build_dc_embedding_text(
    description: str,
    log_sources: List[LogSourceEntry],
) -> str:
    """Build a single text block suitable for embedding.

    Combines the DC description with all non-trivial Channel strings from
    log_sources so that semantic similarity captures both the high-level
    DC purpose and the specific log-event patterns it covers.
    """
    parts = [description.strip()] if description.strip() else []

    seen_channels: set = set()
    for ls in log_sources:
        ch = ls.channel.strip()
        ch_lower = ch.lower()
        if ch_lower in _SKIP_CHANNELS:
            continue
        if ch_lower in seen_channels:
            continue
        seen_channels.add(ch_lower)
        parts.append(ch)

    text = " ".join(parts)
    if len(text) > 8000:
        text = text[:8000]
    return text


def load_datacomponents(datacomponents_dir: Path) -> List[DataComponentProfile]:
    profiles: List[DataComponentProfile] = []
    for path in sorted(datacomponents_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        searchable = data.get("searchable_indexes", {})
        log_sources = []
        for entry in data.get("log_sources", []):
            name = entry.get("Name") or entry.get("name") or "unknown"
            channel = entry.get("Channel") or entry.get("channel") or "None"
            log_sources.append(LogSourceEntry(name=name.strip(), channel=str(channel).strip()))

        description = str(data.get("description", ""))
        emb_text = build_dc_embedding_text(description, log_sources)

        profile = DataComponentProfile(
            id=str(data.get("id", path.stem)),
            name=str(data.get("name", path.stem)),
            description=description,
            platforms=[str(x).lower() for x in _as_list(searchable.get("platforms"))],
            log_source_types=[str(x).lower() for x in _as_list(searchable.get("log_source_types"))],
            categories=[str(x).lower() for x in _as_list(searchable.get("categories"))],
            fields=[str(x) for x in _as_list(searchable.get("fields"))],
            keywords=[str(x) for x in _as_list(searchable.get("keywords"))],
            log_sources=log_sources,
            embedding_text=emb_text,
            raw=data,
        )
        profiles.append(profile)
    return profiles


def build_log_source_to_dc_map(profiles: List[DataComponentProfile]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for profile in profiles:
        for ls in profile.log_sources:
            source = ls.name
            if source not in mapping:
                mapping[source] = []
            if profile.id not in mapping[source]:
                mapping[source].append(profile.id)
    return mapping


def build_dc_keyword_map(profiles: List[DataComponentProfile]) -> Dict[str, List[str]]:
    return {profile.id: profile.keywords for profile in profiles}


def load_assets(assets_file: Path) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    with assets_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    by_id: Dict[str, dict] = {}
    by_ip: Dict[str, dict] = {}
    for asset in data.get("assets", []):
        asset_id = str(asset.get("asset_id", "unknown"))
        by_id[asset_id] = asset
        asset_ip = asset.get("asset_ip")
        if asset_ip:
            by_ip[str(asset_ip)] = asset
    return by_id, by_ip
