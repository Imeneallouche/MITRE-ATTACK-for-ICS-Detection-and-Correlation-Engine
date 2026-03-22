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


def load_datacomponents(datacomponents_dir: Path) -> List[DataComponentProfile]:
    profiles: List[DataComponentProfile] = []
    for path in sorted(datacomponents_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        searchable = data.get("searchable_indexes", {})
        log_sources = []
        for entry in data.get("log_sources", []):
            # JSON files are inconsistent: some use Name/Channel, some name/channel.
            name = entry.get("Name") or entry.get("name") or "unknown"
            channel = entry.get("Channel") or entry.get("channel") or "None"
            log_sources.append(LogSourceEntry(name=name.strip(), channel=str(channel).strip()))

        profile = DataComponentProfile(
            id=str(data.get("id", path.stem)),
            name=str(data.get("name", path.stem)),
            description=str(data.get("description", "")),
            platforms=[str(x).lower() for x in _as_list(searchable.get("platforms"))],
            log_source_types=[str(x).lower() for x in _as_list(searchable.get("log_source_types"))],
            categories=[str(x).lower() for x in _as_list(searchable.get("categories"))],
            fields=[str(x) for x in _as_list(searchable.get("fields"))],
            keywords=[str(x) for x in _as_list(searchable.get("keywords"))],
            log_sources=log_sources,
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
