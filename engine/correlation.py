"""Temporal correlation engine for multi-stage attack detection.

Groups related CandidateMatch objects by asset and time window, applies
chain-step boosting for ordered DataComponent transitions, and supports
cross-asset grouping for network-flow oriented DataComponents.

All chain transitions and network DataComponents are supplied via
configuration; the engine itself encodes no environment-specific
knowledge.

Temporal Decay
--------------
Correlation boosts are decayed exponentially with the time delta between
the current event and the group's last event:

    effective_boost = base_boost * exp(-delta_t / decay_half_life)
"""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .models import CandidateMatch, CorrelationGroup


def _extract_event_ips(match: CandidateMatch) -> Set[str]:
    """Return the set of routable IPs attached to this event.

    Collapses src_ip / dest_ip / asset_ip from ``event.fields`` and
    ``event.raw_source`` into a single set used for cross-asset grouping.
    Filters out wildcard / unspecified addresses to avoid spurious bridging.
    """
    fields = match.event.fields or {}
    raw = match.event.raw_source or {}
    candidates: Set[str] = set()
    for container in (fields, raw):
        for key in ("src_ip", "source_ip", "source.ip", "dest_ip",
                    "destination_ip", "destination.ip", "asset_ip"):
            val = container.get(key)
            if isinstance(val, str) and val:
                candidates.add(val.strip())
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item:
                        candidates.add(item.strip())
    if match.event.asset_ip:
        candidates.add(str(match.event.asset_ip).strip())
    # Drop degenerate addresses so they cannot bridge unrelated groups.
    filtered: Set[str] = set()
    for ip in candidates:
        if not ip or ip in {"0.0.0.0", "::", "-", "unknown"}:
            continue
        filtered.add(ip)
    return filtered


@dataclass
class CorrelationConfig:
    window_seconds: int
    repeat_count_escalation: int
    per_event_correlation_boost: float
    max_correlation_boost: float
    chain_step_boost: float
    decay_half_life_seconds: float = 120.0
    chain_rules: FrozenSet[Tuple[str, str]] = field(default_factory=frozenset)
    network_datacomponents: FrozenSet[str] = field(default_factory=frozenset)
    # Shape of the per-event accumulator. "linear" multiplies per_event by
    # n_prior; "log" uses log1p(n_prior) for diminishing returns so long
    # runs of the same repeated event cannot saturate the final score.
    accumulator: str = "linear"
    # When True, matches flagged weak_evidence do not contribute to the
    # prior-count accumulator and do not receive any correlation boost.
    require_strong_match: bool = False

    @classmethod
    def build(
        cls,
        *,
        window_seconds: int,
        repeat_count_escalation: int,
        per_event_correlation_boost: float,
        max_correlation_boost: float,
        chain_step_boost: float,
        decay_half_life_seconds: float = 120.0,
        chain_rules: Optional[Iterable[Tuple[str, str]]] = None,
        network_datacomponents: Optional[Iterable[str]] = None,
        accumulator: str = "linear",
        require_strong_match: bool = False,
    ) -> "CorrelationConfig":
        acc = str(accumulator or "linear").lower()
        if acc not in {"linear", "log"}:
            acc = "linear"
        return cls(
            window_seconds=window_seconds,
            repeat_count_escalation=repeat_count_escalation,
            per_event_correlation_boost=per_event_correlation_boost,
            max_correlation_boost=max_correlation_boost,
            chain_step_boost=chain_step_boost,
            decay_half_life_seconds=decay_half_life_seconds,
            chain_rules=frozenset(tuple(p) for p in (chain_rules or [])),
            network_datacomponents=frozenset(network_datacomponents or []),
            accumulator=acc,
            require_strong_match=bool(require_strong_match),
        )


class CorrelationEngine:

    def __init__(self, cfg: CorrelationConfig) -> None:
        self.cfg = cfg
        self.groups: Dict[str, CorrelationGroup] = {}
        # Side-table of IPs participating in each group (used by the generic
        # IP-bridge to group cross-asset attack steps without naming DCs).
        self._group_ips: Dict[str, Set[str]] = {}

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
            self._group_ips[group.group_id] = _extract_event_ips(match)
            return group, {"correlation_boost": 0.0, "chain_boost": 0.0}

        group.add_match(match)
        chain_boost = self._maybe_chain_boost(group, match)

        # Weak-evidence matches: group them for context, but never inflate
        # confidence from repetition. This prevents long runs of single-signal
        # events (startup banners, flow heartbeats, etc.) from saturating
        # the aggregate score regardless of their individual quality.
        if self.cfg.require_strong_match and getattr(match, "weak_evidence", False):
            group.aggregate_score = max(group.aggregate_score, match.similarity_score)
            return group, {"correlation_boost": 0.0, "chain_boost": 0.0}

        delta_t = (match.event.timestamp - group.last_timestamp).total_seconds()
        delta_t = max(delta_t, 0.0)
        decay = self._temporal_decay(delta_t)

        # Effective prior count: optionally exclude weak matches so that
        # the accumulator reflects independent corroborating evidence.
        # Accumulation is *diversity-driven*: only the count of distinct
        # DataComponents contributes to the boost, so a stream of the same
        # DC (e.g. bursts of idle NSM flows, or a looping process alarm)
        # cannot inflate the aggregate score on its own.  Multi-stage attack
        # chains naturally pick up boost as new DCs join the group.
        if self.cfg.require_strong_match:
            strong_priors = [
                m for m in group.matches[:-1]
                if not getattr(m, "weak_evidence", False)
            ]
            effective_matches = strong_priors + (
                [match] if not getattr(match, "weak_evidence", False) else []
            )
            distinct_dcs = {m.datacomponent_id for m in effective_matches}
            dc_counts: Dict[str, int] = {}
            for m in effective_matches:
                dc_counts[m.datacomponent_id] = dc_counts.get(m.datacomponent_id, 0) + 1
        else:
            distinct_dcs = {m.datacomponent_id for m in group.matches}
            dc_counts = {}
            for m in group.matches:
                dc_counts[m.datacomponent_id] = dc_counts.get(m.datacomponent_id, 0) + 1

        # Seed DC doesn't count (needs *corroboration*, not self-credit).
        n_prior_effective = max(len(distinct_dcs) - 1, 0)

        repeat_boost = 0.0
        max_count = max(dc_counts.values(), default=0)
        # Repeat-escalation only when at least two distinct DCs participate.
        # Pure same-DC repetition is treated as noise, not corroborating evidence.
        if (
            max_count >= self.cfg.repeat_count_escalation
            and len(distinct_dcs) >= 2
        ):
            repeat_boost = self.cfg.per_event_correlation_boost

        if self.cfg.accumulator == "log":
            accum = math.log1p(n_prior_effective)
        else:
            accum = float(n_prior_effective)

        raw_corr_boost = (
            self.cfg.per_event_correlation_boost * accum
            + repeat_boost
        )
        corr_boost = min(self.cfg.max_correlation_boost, raw_corr_boost) * decay
        chain_boost *= decay

        group.aggregate_score = min(
            1.0,
            max(group.aggregate_score, match.similarity_score) + corr_boost + chain_boost,
        )
        # Keep the IP participation set in sync for IP-bridge grouping.
        self._group_ips.setdefault(group.group_id, set()).update(_extract_event_ips(match))
        return group, {"correlation_boost": corr_boost, "chain_boost": chain_boost}

    def _temporal_decay(self, delta_seconds: float) -> float:
        """Exponential decay factor based on time since last event."""
        if self.cfg.decay_half_life_seconds <= 0:
            return 1.0
        return math.exp(-0.693 * delta_seconds / self.cfg.decay_half_life_seconds)

    def _select_group(self, match: CandidateMatch) -> Optional[CorrelationGroup]:
        now = match.event.timestamp
        window = timedelta(seconds=self.cfg.window_seconds)
        best: Optional[CorrelationGroup] = None
        best_score = -1.0

        match_ips = _extract_event_ips(match)
        for group in list(self.groups.values()):
            if now - group.last_timestamp > window:
                continue

            same_asset = group.asset_id == match.event.asset_id
            ip_bridge = False
            if not same_asset:
                group_ips = self._group_ips.get(group.group_id, set())
                if match_ips and group_ips and match_ips & group_ips:
                    ip_bridge = True
                elif not self._cross_asset_eligible(group, match):
                    continue

            score = 0.0
            if group.matches and group.matches[-1].datacomponent_id == match.datacomponent_id:
                score += 2.0

            prev_dc = group.chain_ids[-1] if group.chain_ids else ""
            if (prev_dc, match.datacomponent_id) in self.cfg.chain_rules:
                score += 3.0

            if same_asset:
                score += 1.0
            elif ip_bridge:
                # Cross-asset but a shared src/dst IP ties the steps together.
                # Slightly below same-asset affinity but still meaningful.
                score += 0.75

            recency_seconds = (now - group.last_timestamp).total_seconds()
            if recency_seconds < 60:
                score += 1.0
            elif recency_seconds < 120:
                score += 0.5

            if score > best_score:
                best_score = score
                best = group

        return best

    def _cross_asset_eligible(
        self, group: CorrelationGroup, match: CandidateMatch,
    ) -> bool:
        net = self.cfg.network_datacomponents
        if not net:
            return False
        if match.datacomponent_id in net:
            return True
        if group.chain_ids and group.chain_ids[-1] in net:
            return True
        return False

    def _maybe_chain_boost(self, group: CorrelationGroup, match: CandidateMatch) -> float:
        if not group.chain_ids:
            group.chain_ids = [match.datacomponent_id]
            return 0.0

        prev = group.chain_ids[-1]
        cur = match.datacomponent_id

        if (prev, cur) in self.cfg.chain_rules and cur not in group.chain_ids:
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
            self._group_ips.pop(gid, None)
        return len(expired)

    def get_group_summary(self, group_id: str) -> Optional[Dict]:
        group = self.groups.get(group_id)
        if not group:
            return None
        return {
            "group_id": group.group_id,
            "asset_id": group.asset_id,
            "first_timestamp": group.first_timestamp.isoformat(),
            "last_timestamp": group.last_timestamp.isoformat(),
            "chain_ids": group.chain_ids,
            "chain_depth": group.chain_depth,
            "event_count": len(group.matches),
            "aggregate_score": round(group.aggregate_score, 4),
            "technique_sequence": group.technique_sequence,
        }
