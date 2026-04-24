"""Layer B training entry point."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

from ..config import LearningConfig
from ..data import (
    AlertLoader, FeatureBuilder, LabelStore, LabelledDatasetBuilder,
)
from .attributor import ChainAttributor
from .sequence_model import SequenceModelConfig
from .vocab import Vocabulary

LOG = logging.getLogger("learning.layer_b.train")


def _technique_to_tactics_from_engine(engine_cfg_path: Optional[Path]) -> Dict[str, List[str]]:
    """Derive a fallback technique→tactics map from the engine's
    ``technique_mapper.fallback`` block (works without Neo4j)."""
    if engine_cfg_path is None or not engine_cfg_path.exists():
        return {}
    import yaml
    with engine_cfg_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    out: Dict[str, List[str]] = {}
    fallback = (raw.get("technique_mapper") or {}).get("fallback") or {}
    if isinstance(fallback, dict):
        for dc, entries in fallback.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                t = str(entry.get("technique_id") or "").upper()
                tac = entry.get("tactic")
                if not t:
                    continue
                if isinstance(tac, list):
                    out.setdefault(t, [])
                    for x in tac:
                        if str(x).lower() not in out[t]:
                            out[t].append(str(x).lower())
                elif isinstance(tac, str) and tac:
                    out.setdefault(t, [])
                    if tac.lower() not in out[t]:
                        out[t].append(tac.lower())
    return out


def train_layer_b(
    cfg: LearningConfig,
    *,
    es_hosts: Optional[List[str]] = None,
    fixture_path: Optional[Path] = None,
    engine_config_path: Optional[Path] = None,
) -> ChainAttributor:
    layer_b = cfg.layer_b
    if not layer_b.get("enabled", True):
        raise RuntimeError("Layer B disabled in config.")

    label_store = LabelStore(cfg.path("labels_file"))
    if not label_store.all():
        raise RuntimeError("No window labels available; cannot train Layer B.")

    fb = FeatureBuilder()
    builder = LabelledDatasetBuilder(
        label_store=label_store,
        feature_builder=fb,
        skew_seconds=cfg.labels.get("skew_seconds", 15),
    )

    if fixture_path is not None:
        alerts = AlertLoader.load_jsonl(fixture_path)
        examples = builder.build_from_alerts(alerts)
    else:
        loader = AlertLoader(hosts=es_hosts, scroll_size=cfg.es.get("scroll_size", 1000))
        examples = builder.build_from_es(loader, cfg.es.get("alert_index_pattern", "ics-alerts-*"))

    if not examples:
        raise RuntimeError("No labelled examples for Layer B.")
    groups = list(LabelledDatasetBuilder.group_by_window(examples).values())
    if not groups:
        raise RuntimeError("Examples produced no window groups.")

    technique_to_tactics = _technique_to_tactics_from_engine(engine_config_path)
    vocab = ChainAttributor.fit_vocabulary(examples, technique_to_tactics=technique_to_tactics)

    seq_cfg = SequenceModelConfig(
        n_dc=max(len(vocab.dc), 4),
        n_asset=max(len(vocab.asset), 4),
        n_technique=max(len(vocab.technique), 4),
        n_tactic=max(len(vocab.tactic), 4),
        n_chain=max(len(vocab.chain), 4),
        scalar_dim=int(layer_b.get("scalar_dim", 20)),
        d_model=int(layer_b.get("d_model", 128)),
        n_heads=int(layer_b.get("num_heads", 4)),
        n_layers=int(layer_b.get("num_layers", 3)),
        ff_dim=int(layer_b.get("ff_dim", 256)),
        dropout=float(layer_b.get("dropout", 0.1)),
        causal_window=int(layer_b.get("causal_window", 8)),
        max_seq_len=int(layer_b.get("max_seq_len", 64)),
    )

    att = ChainAttributor(
        cfg=seq_cfg, vocab=vocab,
        device=layer_b.get("device", "auto"),
        technique_threshold=layer_b.get("technique_threshold", 0.45),
        tactic_threshold=layer_b.get("tactic_threshold", 0.35),
        unknown_chain_label=layer_b.get("unknown_chain_label", "__UNKNOWN__"),
        technique_to_tactics=technique_to_tactics,
    )
    train_cfg = layer_b.get("train") or {}
    att.fit(
        groups,
        epochs=int(train_cfg.get("epochs", 20)),
        batch_size=int(train_cfg.get("batch_size", 16)),
        lr=float(train_cfg.get("lr", 0.0005)),
        weight_decay=float(train_cfg.get("weight_decay", 1e-4)),
        grad_clip=float(train_cfg.get("grad_clip", 1.0)),
        val_split=float(train_cfg.get("val_split", 0.2)),
    )
    att.save(cfg.path("layer_b_model"), cfg.path("layer_b_vocab"))
    return att
