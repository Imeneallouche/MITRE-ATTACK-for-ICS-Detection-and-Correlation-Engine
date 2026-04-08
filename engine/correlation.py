from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, FrozenSet, List, Optional, Tuple

from .models import CandidateMatch, CorrelationGroup


@dataclass
class CorrelationConfig:
    window_seconds: int
    repeat_count_escalation: int
    per_event_correlation_boost: float
    max_correlation_boost: float
    chain_step_boost: float


CHAIN_RULES: FrozenSet[Tuple[str, str]] = frozenset({
    # Enterprise chains
    ("DC0067", "DC0032"),
    ("DC0032", "DC0034"),
    ("DC0032", "DC0001"),
    ("DC0001", "DC0039"),
    ("DC0082", "DC0032"),
    ("DC0033", "DC0040"),
    ("DC0040", "DC0061"),
    ("DC0067", "DC0082"),
    ("DC0082", "DC0078"),
    # ICS recon -> collection
    ("DC0078", "DC0085"),
    ("DC0078", "DC0082"),
    ("DC0085", "DC0082"),
    ("DC0078", "DC0109"),
    ("DC0082", "DC0109"),
    # ICS credential access -> execution
    ("DC0067", "DC0038"),
    ("DC0067", "DC0109"),
    ("DC0002", "DC0067"),
    ("DC0002", "DC0038"),
    # ICS process manipulation chains
    ("DC0085", "DC0109"),
    ("DC0082", "DC0108"),
    ("DC0109", "DC0108"),
    ("DC0038", "DC0109"),
    ("DC0038", "DC0033"),
    ("DC0107", "DC0109"),
    # ICS lateral movement
    ("DC0067", "DC0039"),
    ("DC0039", "DC0032"),
    ("DC0032", "DC0085"),
    # ICS evasion -> impact
    ("DC0033", "DC0109"),
    ("DC0033", "DC0108"),
    ("DC0061", "DC0109"),
    ("DC0040", "DC0109"),
    ("DC0040", "DC0032"),
    # Network -> process
    ("DC0078", "DC0032"),
    ("DC0078", "DC0033"),
    ("DC0078", "DC0038"),
    # Application -> alarm
    ("DC0038", "DC0108"),
    ("DC0060", "DC0033"),
    ("DC0060", "DC0032"),
})


class CorrelationEngine:
    def __init__(self, cfg: CorrelationConfig) -> None:
        self.cfg = cfg
        self.groups: Dict[str, CorrelationGroup] = {}

    def process(self, match: CandidateMatch) -> Tuple[CorrelationGroup, Dict[str, float]]:
        group = self._select_group(match)
        if group is None:
            group = CorrelationGroup(
                group_id=str(uuid.uuid4()),
                asset_id=match.event.asset_id,
                asset_name=match.event.asset_name,
                first_timestamp=match.event.timestamp,
                last_timestamp=match.event.timestamp,
                matches=[match],
                chain_ids=[match.datacomponent_id],
                chain_depth=1,
                aggregate_score=match.similarity_score,
            )
            self.groups[group.group_id] = group
            return group, {"correlation_boost": 0.0, "chain_boost": 0.0}

        group.add_match(match)
        chain_boost = self._maybe_chain_boost(group, match)

        repeat_boost = 0.0
        if len(group.matches) >= self.cfg.repeat_count_escalation:
            dc_counts: Dict[str, int] = {}
            for m in group.matches:
                dc_counts[m.datacomponent_id] = dc_counts.get(m.datacomponent_id, 0) + 1
            max_count = max(dc_counts.values())
            if max_count >= self.cfg.repeat_count_escalation:
                repeat_boost = self.cfg.per_event_correlation_boost

        corr_boost = min(
            self.cfg.max_correlation_boost,
            self.cfg.per_event_correlation_boost * max(len(group.matches) - 1, 0) + repeat_boost,
        )
        group.aggregate_score = min(
            1.0,
            max(group.aggregate_score, match.similarity_score) + corr_boost + chain_boost,
        )
        return group, {"correlation_boost": corr_boost, "chain_boost": chain_boost}

    def _select_group(self, match: CandidateMatch) -> Optional[CorrelationGroup]:
        now = match.event.timestamp
        window = timedelta(seconds=self.cfg.window_seconds)
        best: Optional[CorrelationGroup] = None
        best_score = -1.0
        for group in list(self.groups.values()):
            if now - group.last_timestamp > window:
                continue
            if group.asset_id != match.event.asset_id:
                if not self._cross_asset_eligible(group, match):
                    continue
            score = 0.0
            if group.matches and group.matches[-1].datacomponent_id == match.datacomponent_id:
                score += 2.0
            prev_dc = group.chain_ids[-1] if group.chain_ids else ""
            if (prev_dc, match.datacomponent_id) in CHAIN_RULES:
                score += 3.0
            if group.asset_id == match.event.asset_id:
                score += 1.0
            if score > best_score:
                best_score = score
                best = group
        return best

    @staticmethod
    def _cross_asset_eligible(group: CorrelationGroup, match: CandidateMatch) -> bool:
        network_dcs = {"DC0078", "DC0082", "DC0085"}
        if match.datacomponent_id in network_dcs:
            return True
        if group.chain_ids and group.chain_ids[-1] in network_dcs:
            return True
        return False

    def _maybe_chain_boost(self, group: CorrelationGroup, match: CandidateMatch) -> float:
        if not group.chain_ids:
            group.chain_ids = [match.datacomponent_id]
            return 0.0
        prev = group.chain_ids[-1]
        cur = match.datacomponent_id
        if (prev, cur) in CHAIN_RULES and cur not in group.chain_ids:
            group.chain_ids.append(cur)
            group.chain_depth += 1
            return self.cfg.chain_step_boost
        if cur not in group.chain_ids:
            group.chain_ids.append(cur)
        return 0.0

    def prune_expired(self, now: datetime) -> int:
        window = timedelta(seconds=self.cfg.window_seconds * 2)
        expired = [gid for gid, g in self.groups.items() if now - g.last_timestamp > window]
        for gid in expired:
            del self.groups[gid]
        return len(expired)
