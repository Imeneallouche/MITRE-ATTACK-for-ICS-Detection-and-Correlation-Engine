from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .models import CandidateMatch, CorrelationGroup


@dataclass
class CorrelationConfig:
    window_seconds: int
    repeat_count_escalation: int
    per_event_correlation_boost: float
    max_correlation_boost: float
    chain_step_boost: float


class CorrelationEngine:
    def __init__(self, cfg: CorrelationConfig) -> None:
        self.cfg = cfg
        self.groups: Dict[str, CorrelationGroup] = {}
        self.chain_rules = {
            ("DC0067", "DC0032"),
            ("DC0032", "DC0034"),
            ("DC0032", "DC0001"),
            ("DC0001", "DC0039"),
            ("DC0082", "DC0032"),
            ("DC0033", "DC0040"),
            ("DC0040", "DC0061"),
            ("DC0067", "DC0082"),
            ("DC0082", "DC0078"),
        }

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
        corr_boost = min(
            self.cfg.max_correlation_boost,
            self.cfg.per_event_correlation_boost * max(len(group.matches) - 1, 0),
        )
        group.aggregate_score = min(1.0, max(group.aggregate_score, match.similarity_score) + corr_boost + chain_boost)
        return group, {"correlation_boost": corr_boost, "chain_boost": chain_boost}

    def _select_group(self, match: CandidateMatch) -> Optional[CorrelationGroup]:
        now = match.event.timestamp
        window = timedelta(seconds=self.cfg.window_seconds)
        best: Optional[CorrelationGroup] = None
        for group in self.groups.values():
            if group.asset_id != match.event.asset_id:
                continue
            if now - group.last_timestamp > window:
                continue
            # Prefer same DC groups.
            if group.matches and group.matches[-1].datacomponent_id == match.datacomponent_id:
                return group
            if best is None:
                best = group
        return best

    def _maybe_chain_boost(self, group: CorrelationGroup, match: CandidateMatch) -> float:
        if not group.chain_ids:
            group.chain_ids = [match.datacomponent_id]
            return 0.0
        prev = group.chain_ids[-1]
        cur = match.datacomponent_id
        if (prev, cur) in self.chain_rules and cur not in group.chain_ids:
            group.chain_ids.append(cur)
            group.chain_depth += 1
            return self.cfg.chain_step_boost
        return 0.0
