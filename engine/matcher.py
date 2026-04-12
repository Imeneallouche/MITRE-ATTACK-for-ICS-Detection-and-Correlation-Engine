"""DataComponent matcher with scientific multi-signal scoring.

Uses the ScoringEngine for mathematically grounded similarity computation
and provides ICS-specific field mappings for GRFICS log alignment.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .feature_extractor import infer_categories
from .models import CandidateMatch, DataComponentProfile, NormalizedEvent
from .scorer import ScoringEngine

ICS_FIELD_MAP: Dict[str, List[str]] = {
    "DC0109": [
        "ics.alarm_type", "ics.severity", "ics.protocol", "modbus.function_code",
        "modbus.exception_code", "process_alarm", "alarm_state", "setpoint",
    ],
    "DC0108": [
        "ics.severity", "ics.protocol", "modbus.exception_code", "kern",
        "reboot", "shutdown", "device_fault",
    ],
    "DC0107": [
        "ics.protocol", "modbus.function_code", "pacct", "process_value",
        "current_value", "tag_name",
    ],
    "DC0078": [
        "src_ip", "dst_ip", "src_port", "dest_port", "protocol", "bytes",
        "packets", "duration", "netfilter", "action",
    ],
    "DC0082": ["src_ip", "dst_ip", "src_port", "dest_port", "protocol"],
    "DC0085": [
        "src_ip", "dst_ip", "payload", "event_type", "alert.signature",
        "ics.protocol", "modbus.function_code", "app_proto",
    ],
    "DC0032": [
        "syslog_program", "syslog_pid", "audit_type", "process_name", "pid",
        "audit.exe", "audit.comm", "command",
    ],
    "DC0033": [
        "syslog_program", "syslog_pid", "audit_type", "exit_code",
        "audit.exe", "signal",
    ],
    "DC0067": [
        "auth_user", "src_ip", "auth_method", "pam_service", "session_id",
        "sshd", "accepted",
    ],
    "DC0038": [
        "syslog_program", "event_type", "status_code", "request_method",
        "http_path", "catalina", "flask",
    ],
    "DC0061": ["file_path", "file_name", "audit.name", "audit.nametype"],
    "DC0039": ["file_path", "file_name", "audit.name"],
    "DC0040": ["file_path", "file_name", "audit.name"],
    "DC0002": ["auth_user", "src_ip", "auth_method", "pam_service"],
    "DC0064": [
        "command", "cmdline", "audit.exe", "audit.comm", "syslog_program",
    ],
    "DC0004": ["firmware", "module", "kern", "insmod", "modprobe"],
    "DC0016": ["module", "kern", "insmod", "modprobe", "lsmod"],
    "DC0029": ["script", "python", "bash", "sh", "interpreter"],
    "DC0060": ["service", "systemctl", "supervisor", "daemon"],
    "DC0110": ["asset", "inventory", "device", "hostname"],
    "DC0111": ["software", "version", "package", "binary"],
}


class DataComponentMatcher:
    """Matches normalized events against DC profiles using scientific scoring."""

    def __init__(
        self,
        profiles: Sequence[DataComponentProfile],
        scoring_weights: Dict[str, float],
        candidate_threshold: float,
        high_confidence_threshold: float,
    ) -> None:
        self.profiles = list(profiles)
        self._profile_by_id = {p.id: p for p in self.profiles}
        self.candidate_threshold = candidate_threshold
        self.high_confidence_threshold = high_confidence_threshold

        self.scorer = ScoringEngine(weights=scoring_weights)
        for p in self.profiles:
            self.scorer.precompile_keywords(p.id, p.keywords)

    def match_event(self, event: NormalizedEvent) -> List[CandidateMatch]:
        candidates: List[CandidateMatch] = []
        enriched_ids = set(event.mitre_dc_candidates)
        scored_ids: Set[str] = set()

        if enriched_ids:
            for dc_id in enriched_ids:
                profile = self._profile_by_id.get(dc_id)
                if profile is None:
                    continue
                candidate = self._score(event, profile)
                scored_ids.add(dc_id)
                if candidate.similarity_score >= self.candidate_threshold:
                    candidates.append(candidate)

        if not candidates:
            for profile in self.profiles:
                if profile.id in scored_ids:
                    continue
                candidate = self._score(event, profile)
                if candidate.similarity_score >= self.candidate_threshold:
                    candidates.append(candidate)

        candidates.sort(key=lambda c: c.similarity_score, reverse=True)

        if len(candidates) > 1:
            top = candidates[0].similarity_score
            for cand in candidates[1:]:
                if top - cand.similarity_score <= 0.10:
                    cand.is_ambiguous = True
                    candidates[0].is_ambiguous = True

        return candidates

    def _score(self, event: NormalizedEvent, profile: DataComponentProfile) -> CandidateMatch:
        ls_names = [ls.name for ls in profile.log_sources]
        ls_score, ls_evidence = self.scorer.score_log_source(
            event.mitre_dc_candidates,
            event.log_source_normalized,
            profile.id,
            ls_names,
        )

        event_text = event.log_message + " " + " ".join(str(v) for v in event.fields.values())
        logstash_kw = event.mitre_keyword_hits.get(profile.id)
        kw_score, kw_hits = self.scorer.score_keywords(
            event_text, profile.id, profile.keywords, logstash_kw,
        )

        ics_fields = ICS_FIELD_MAP.get(profile.id)
        fld_score, fld_hits = self.scorer.score_fields(
            set(event.fields.keys()), profile.fields, ics_fields,
        )

        event_cats = set(event.categories) if event.categories else set(
            infer_categories(event.log_type, event.log_source_normalized, event.log_message)
        )
        cat_score, cat_hits = self.scorer.score_categories(event_cats, profile.categories)

        channels = [ls.channel for ls in profile.log_sources]
        ch_score, ch_hit = self.scorer.score_channel(event_text, channels)

        signal_scores = {
            "log_source_match": ls_score,
            "keyword_match": kw_score,
            "field_match": fld_score,
            "category_match": cat_score,
            "channel_match": ch_score,
        }
        similarity = self.scorer.compute_composite(signal_scores)

        confidence_tier = "low"
        if similarity >= self.high_confidence_threshold:
            confidence_tier = "high"
        elif similarity >= 0.55:
            confidence_tier = "medium"

        evidence = {
            "matched_log_source": ls_evidence,
            "matched_keywords": kw_hits,
            "matched_fields": fld_hits,
            "matched_categories": cat_hits,
            "matched_channel": ch_hit,
        }

        return CandidateMatch(
            match_id=str(uuid.uuid4()),
            datacomponent_id=profile.id,
            datacomponent_name=profile.name,
            similarity_score=similarity,
            signal_scores=signal_scores,
            evidence=evidence,
            confidence_tier=confidence_tier,
            event=event,
        )
