#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import yaml


def _read_profiles(dc_dir: Path) -> List[dict]:
    profiles = []
    for path in sorted(dc_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as f:
            profiles.append(json.load(f))
    return profiles


def _extract_log_sources(dc: dict) -> List[str]:
    out = []
    for ls in dc.get("log_sources", []):
        name = ls.get("Name") or ls.get("name")
        if name:
            out.append(str(name).strip())
    return out


def _extract_keywords(dc: dict) -> List[str]:
    searchable = dc.get("searchable_indexes", {})
    kws = searchable.get("keywords", [])
    if not isinstance(kws, list):
        return []
    return [str(x).strip() for x in kws if str(x).strip()]


def generate(dc_dir: Path, mapping_out: Path, keywords_out: Path) -> None:
    profiles = _read_profiles(dc_dir)
    mapping: Dict[str, List[str]] = {}
    keywords: Dict[str, List[str]] = {}

    for dc in profiles:
        dc_id = str(dc.get("id"))
        keywords[dc_id] = _extract_keywords(dc)
        for source in _extract_log_sources(dc):
            mapping.setdefault(source, [])
            if dc_id not in mapping[source]:
                mapping[source].append(dc_id)

    mapping_yaml = {k: ",".join(v) for k, v in sorted(mapping.items(), key=lambda x: x[0].lower())}
    mapping_out.parent.mkdir(parents=True, exist_ok=True)
    with mapping_out.open("w", encoding="utf-8") as f:
        yaml.safe_dump(mapping_yaml, f, sort_keys=True, allow_unicode=False)

    with keywords_out.open("w", encoding="utf-8") as f:
        json.dump(keywords, f, indent=2)

    print(f"Generated {mapping_out} and {keywords_out} from {len(profiles)} DataComponents.")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    dc_dir = repo_root / "datacomponents"
    mapping_out = repo_root / "logstash" / "mitre_mapping" / "log_source_to_dc.yml"
    keywords_out = repo_root / "logstash" / "mitre_mapping" / "dc_keywords.json"
    generate(dc_dir, mapping_out, keywords_out)


if __name__ == "__main__":
    main()
