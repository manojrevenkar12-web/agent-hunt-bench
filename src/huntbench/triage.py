"""What the model is shown, and the check on what it says back.

The model reads a case and writes a verdict with claims, each claim naming an event and a field value it relies on.
The model is assumed to hallucinate: before a verdict counts, code checks every claim against the event store. A claim
about an event that does not exist, an event outside the case, or a value the event does not hold fails the report,
and a failed report goes to a person whatever its verdict."""

from __future__ import annotations

from dataclasses import dataclass, field

from .cases import Case
from .graph import Graph


@dataclass
class Check:
    ok: bool
    problems: list[str] = field(default_factory=list)


def check_claims(report: dict, events: dict[str, dict], evidence: list[str]) -> Check:
    allowed = set(evidence)
    problems = []
    for c in report.get("claims", []):
        ev = events.get(c.get("eid"))
        if ev is None:
            problems.append(f"{c.get('eid')}: no such event")
        elif c["eid"] not in allowed:
            problems.append(f"{c['eid']}: not part of this case")
        elif c.get("field") not in ev:
            problems.append(f"{c['eid']}: has no field {c.get('field')}")
        elif ev[c["field"]] != c.get("value"):
            problems.append(f"{c['eid']}.{c['field']} is {ev[c['field']]!r}, the report says {c.get('value')!r}")
    if not report.get("claims"):
        problems.append("the report cites no evidence")
    return Check(not problems, problems)


def context_packet(case: Case, graph: Graph, history: list[Case], events: dict[str, dict], limit: int) -> dict:
    """Everything a careful analyst would pull before deciding: who the person is, their devices and agent, what fired
    on them recently, and the case's own events, newest last."""
    recent = [c for c in history if c.entity == case.entity and c.id != case.id and case.opened - c.last < 7 * 24 * 60]
    return {
        "person": graph.profile(case.entity) if case.entity in graph.people else {"identifier": case.entity},
        "case": {
            "id": case.id,
            "severity": case.severity,
            "techniques": case.techniques,
            "sources": case.sources,
            "detections": sorted({a.rule for a in case.alerts}),
        },
        "recent_cases": [{"id": c.id, "detections": sorted({a.rule for a in c.alerts}), "outcome": c.state} for c in recent[-5:]],
        "events": [events[e] for e in case.eids[-limit:]],
    }
