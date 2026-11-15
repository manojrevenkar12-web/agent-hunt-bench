"""From alerts to people. Code decides the route: which alerts the model may close, which page the on-call engineer,
which wait in the queue, and which agent sends are held. The model only reads and writes a report.

`model(key, packet, with_context)` returns a report; `people(key, ts, load, page, eids)` returns when a person looked
and what they concluded. The evaluation passes the simulated ones; production passes the live model and the queue."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from .cases import Case, CaseBook
from .detect import SEVERITY, Alert
from .graph import Graph
from .respond import Step, plan
from .triage import check_claims, context_packet

DAY = 24 * 60


@dataclass
class Item:
    """Something a person was asked to read."""

    key: str
    case: str
    alerts: list[str]
    ts: int
    page: bool
    reason: str
    handled_at: int = 0
    verdict: str = ""


@dataclass
class Outcome:
    items: list[Item] = field(default_factory=list)
    closed_by_model: list[tuple[str, int, list[str]]] = field(default_factory=list)  # alert, time, evidence
    holds: list[tuple[str, int, str]] = field(default_factory=list)  # alert, time, agent
    reports: int = 0
    failed_checks: int = 0
    unsupported_shown: int = 0  # unsupported claims in reports a person or the route relied on
    closed_on_unsupported: int = 0
    contained: dict[str, tuple[int, list[Step]]] = field(default_factory=dict)  # case -> when, steps
    cases: list[Case] = field(default_factory=list)


def run(
    design: dict,
    cfg: dict,
    alerts: list[Alert],
    events: dict[str, dict],
    graph: Graph | None,
    model: Callable[[str, dict, bool], dict],
    people: Callable[[str, int, int, bool, list[str]], tuple[int, str]],
) -> Outcome:
    t = cfg["triage"]
    out = Outcome()
    book = CaseBook(cfg["cases"]["window_hours"] * 60, group=design.get("cases", False))
    recent: deque[int] = deque()
    hold_rules = set(cfg["respond"]["inline_hold"]) if design.get("inline_hold") else set()

    for a in sorted(alerts, key=lambda a: (a.ts, a.id)):
        if a.rule in hold_rules:  # reversible and immediate: the agent's send waits for a person
            agent = events[a.eids[-1]].get("agent_id", "")
            out.holds.append((a.id, a.ts, agent))
        case = book.add(a)
        if case.state in ("with_person", "incident"):
            continue  # a person already has this case; the alert joins it
        if case.state == "dismissed" and a.rule in case.dismissed_rules and SEVERITY.index(a.severity) <= SEVERITY.index(case.dismissed_at or "low"):
            continue  # a repeat of what a person already dismissed; a new detection or a worse one comes back

        page = case.severity in t["page"]
        reason = "detection"
        if design["model"] != "none":
            with_context = design["model"] == "with_context"
            packet = (
                context_packet(case, graph, book.cases, events, t["evidence_events"])
                if with_context and graph
                else {
                    "person": {"identifier": a.entity},
                    "case": {"id": a.id, "severity": a.severity, "detections": [a.rule]},
                    "recent_cases": [],
                    "events": [events[e] for e in a.eids[-t["evidence_events"] :]],
                }
            )
            report = model(a.id, packet, with_context)
            out.reports += 1
            check = check_claims(report, events, [e["eid"] for e in packet["events"]])
            unsupported = len(check.problems) if not check.ok else 0
            if design.get("never_close") and case.severity in t["never_close"]:
                reason = "severity the model may not close"
            elif design.get("check_claims") and not check.ok:
                out.failed_checks += 1
                reason = "report failed the claim check"
            elif report["escalate"]:
                reason = "model escalated"
                out.unsupported_shown += unsupported
            else:
                case.state = "closed_by_model"
                out.closed_by_model.append((a.id, a.ts, case.eids))
                out.closed_on_unsupported += unsupported > 0
                continue

        while recent and recent[0] <= a.ts - DAY:
            recent.popleft()
        item = Item(f"{a.id}", case.id, [x.id for x in case.alerts], a.ts, page, reason)
        item.handled_at, item.verdict = people(item.key, a.ts, len(recent), page, case.eids)
        recent.append(a.ts)
        out.items.append(item)
        if item.verdict == "incident":
            case.state = "incident"
            out.contained[case.id] = (item.handled_at, plan(case, graph))
        else:
            case.state, case.dismissed_at = "dismissed", case.severity
            case.dismissed_rules = {x.rule for x in case.alerts}
    out.cases = book.cases
    return out
