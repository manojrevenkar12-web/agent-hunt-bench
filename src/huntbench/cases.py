"""Alerts on one person close together in time are one case. A person reads the case once, with every source's
evidence side by side, instead of one alert per log source."""

from __future__ import annotations

from dataclasses import dataclass, field

from .detect import SEVERITY, Alert


@dataclass
class Case:
    id: str
    entity: str
    opened: int
    last: int
    alerts: list[Alert] = field(default_factory=list)
    state: str = "open"  # open, with_person, incident, dismissed, closed_by_model
    dismissed_at: str | None = None  # the severity a person had already dismissed
    dismissed_rules: set[str] = field(default_factory=set)  # and the detections they had seen when they did

    @property
    def severity(self) -> str:
        return max((a.severity for a in self.alerts), key=SEVERITY.index)

    @property
    def techniques(self) -> list[str]:
        return sorted({a.technique for a in self.alerts})

    @property
    def sources(self) -> list[str]:
        return sorted({e.split("-")[0] for a in self.alerts for e in a.eids})

    @property
    def eids(self) -> list[str]:
        return list(dict.fromkeys(e for a in self.alerts for e in a.eids))


class CaseBook:
    def __init__(self, window_minutes: int, group: bool = True):
        self.window, self.group = window_minutes, group
        self.cases: list[Case] = []
        self.open: dict[str, Case] = {}

    def add(self, a: Alert) -> Case:
        c = self.open.get(a.entity) if self.group else None
        if c is None or a.ts - c.last > self.window:
            c = Case(f"case-{len(self.cases) + 1:05d}", a.entity, a.ts, a.ts)
            self.cases.append(c)
            if self.group:
                self.open[a.entity] = c
        c.alerts.append(a)
        c.last = a.ts
        return c
