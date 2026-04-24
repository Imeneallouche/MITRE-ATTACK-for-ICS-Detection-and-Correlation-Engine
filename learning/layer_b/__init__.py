"""Layer B — sequence model for attack chain recognition + technique attribution."""
from __future__ import annotations

from .vocab import Vocabulary
from .sequence_model import CausalWindowTransformer, SequenceModelConfig
from .attributor import ChainAttributor, ChainPrediction

__all__ = [
    "Vocabulary",
    "SequenceModelConfig",
    "CausalWindowTransformer",
    "ChainAttributor",
    "ChainPrediction",
]
