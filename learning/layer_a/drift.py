"""Online drift detectors used by Layer A.

We ship a Page-Hinkley (PH) test by default because it has zero deps and
adapts well to gradual drift in the FP rate.  When the optional ``river``
package is installed an ADWIN detector is also available for sharper
abrupt-drift detection.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

LOG = logging.getLogger("learning.drift")


@dataclass
class DriftEvent:
    index: int
    statistic: float
    mean: float
    note: str = ""


class PageHinkleyDetector:
    """Classical Page-Hinkley test (sequential change-point detector).

    Parameters mirror river's ``drift.PageHinkley``:

    * ``delta`` — magnitude of allowable per-step change.
    * ``threshold`` — alarm threshold for the cumulative deviation.
    * ``min_instances`` — burn-in before alerting.
    """

    def __init__(
        self,
        *,
        delta: float = 0.005,
        threshold: float = 50.0,
        min_instances: int = 30,
    ) -> None:
        self.delta = float(delta)
        self.threshold = float(threshold)
        self.min_instances = int(min_instances)
        self.reset()

    def reset(self) -> None:
        self._n = 0
        self._mean = 0.0
        self._cum = 0.0
        self._min = 0.0
        self._events: List[DriftEvent] = []

    def update(self, value: float) -> Optional[DriftEvent]:
        v = float(value)
        self._n += 1
        delta_mean = (v - self._mean) / float(self._n)
        self._mean += delta_mean
        self._cum += v - self._mean - self.delta
        self._min = min(self._min, self._cum)
        if self._n < self.min_instances:
            return None
        statistic = self._cum - self._min
        if statistic > self.threshold:
            evt = DriftEvent(index=self._n, statistic=statistic, mean=self._mean,
                             note="page_hinkley_alarm")
            self._events.append(evt)
            LOG.warning("Page-Hinkley drift alarm: stat=%.3f mean=%.3f n=%d",
                        statistic, self._mean, self._n)
            self._cum = 0.0
            self._min = 0.0
            return evt
        return None

    @property
    def history(self) -> List[DriftEvent]:
        return list(self._events)


def make_detector(method: str, **kwargs) -> PageHinkleyDetector:
    method = (method or "page_hinkley").lower()
    if method == "page_hinkley":
        return PageHinkleyDetector(**kwargs)
    if method == "adwin":
        try:
            from river.drift import ADWIN  # type: ignore
        except Exception:
            LOG.warning("river not installed; falling back to Page-Hinkley")
            return PageHinkleyDetector(**kwargs)

        # Lightweight adapter around river.ADWIN with the same .update() return
        class _AdwinAdapter(PageHinkleyDetector):
            def __init__(self) -> None:
                super().__init__(**kwargs)
                self._adwin = ADWIN()

            def update(self, value: float):
                self._n += 1
                self._adwin.update(float(value))
                if self._adwin.drift_detected:
                    evt = DriftEvent(index=self._n, statistic=float("nan"),
                                     mean=float("nan"), note="adwin_alarm")
                    self._events.append(evt)
                    return evt
                return None
        return _AdwinAdapter()
    return PageHinkleyDetector(**kwargs)
