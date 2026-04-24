"""Token vocabularies for Layer B.

The sequence model uses three vocabularies:

* DataComponent ids (e.g. ``DC0038``)
* Asset ids (the deterministic engine has at most a few dozen)
* Technique ids (``T0812`` etc.) — used as the multi-label output space.

Tactic ids are derived from the technique vocabulary at training time
(via the Neo4j knowledge graph or the ``technique_mapper.fallback`` block
in ``detection.yml``).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

PAD = "<PAD>"
UNK = "<UNK>"


@dataclass
class Vocabulary:
    dc: Dict[str, int]
    asset: Dict[str, int]
    technique: Dict[str, int]
    tactic: Dict[str, int]
    chain: Dict[str, int]

    # ── Convenience ────────────────────────────────────────────────────
    @classmethod
    def empty(cls) -> "Vocabulary":
        base = {PAD: 0, UNK: 1}
        return cls(dc=dict(base), asset=dict(base), technique=dict(base),
                   tactic=dict(base), chain=dict(base))

    def fit(
        self,
        *,
        dcs: Iterable[str] = (),
        assets: Iterable[str] = (),
        techniques: Iterable[str] = (),
        tactics: Iterable[str] = (),
        chains: Iterable[str] = (),
    ) -> "Vocabulary":
        for tok in dcs:
            self._add(self.dc, str(tok).upper())
        for tok in assets:
            self._add(self.asset, str(tok).lower())
        for tok in techniques:
            self._add(self.technique, str(tok).upper())
        for tok in tactics:
            self._add(self.tactic, str(tok).lower())
        for tok in chains:
            self._add(self.chain, str(tok))
        return self

    @staticmethod
    def _add(d: Dict[str, int], token: str) -> int:
        if not token:
            return d[UNK]
        if token not in d:
            d[token] = len(d)
        return d[token]

    # ── Encoding helpers ───────────────────────────────────────────────
    def encode_dc(self, value: str) -> int:
        return self.dc.get(str(value).upper(), self.dc[UNK])

    def encode_asset(self, value: str) -> int:
        return self.asset.get(str(value).lower(), self.asset[UNK])

    def encode_techniques(self, values: Iterable[str]) -> List[int]:
        return [
            self.technique.get(str(t).upper(), self.technique[UNK])
            for t in values
        ]

    def encode_tactics(self, values: Iterable[str]) -> List[int]:
        return [
            self.tactic.get(str(t).lower(), self.tactic[UNK])
            for t in values
        ]

    def technique_count(self) -> int:
        return len(self.technique)

    def tactic_count(self) -> int:
        return len(self.tactic)

    def chain_count(self) -> int:
        return len(self.chain)

    # ── Persistence ────────────────────────────────────────────────────
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump({
                "dc": self.dc, "asset": self.asset, "technique": self.technique,
                "tactic": self.tactic, "chain": self.chain,
            }, fh, indent=2)

    @classmethod
    def load(cls, path: Path) -> "Vocabulary":
        with Path(path).open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(
            dc=dict(data["dc"]), asset=dict(data["asset"]),
            technique=dict(data["technique"]), tactic=dict(data["tactic"]),
            chain=dict(data["chain"]),
        )

    # ── Inverse maps ───────────────────────────────────────────────────
    def technique_at(self, idx: int) -> str:
        for t, i in self.technique.items():
            if i == idx:
                return t
        return UNK

    def tactic_at(self, idx: int) -> str:
        for t, i in self.tactic.items():
            if i == idx:
                return t
        return UNK

    def chain_at(self, idx: int) -> str:
        for c, i in self.chain.items():
            if i == idx:
                return c
        return UNK
