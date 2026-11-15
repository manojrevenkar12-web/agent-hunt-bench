"""Detection as code: each detection is a YAML file with a condition, a severity, an ATT&CK technique, examples it must
and must not fire on, and a false-positive budget it must hold on attack-free history before it merges.

Four kinds of detection, all run by one streaming engine over events in time order:
  match      one event meets the condition
  threshold  N events (or N distinct values) for one person within a window
  new_value  a value this person has not shown in the learning period
  sequence   steps in order for one person, optionally joined on a field, within a window"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from dataclasses import field as listfield
from pathlib import Path

import yaml

from .settings import ROOT, load

DAY = 24 * 60
SEVERITY = ["low", "medium", "high", "critical"]
KINDS = {"match", "threshold", "new_value", "sequence"}
ATTACK_ID = re.compile(r"(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)")


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    technique: str
    kind: str
    source: str
    where: dict
    by: str = "person"
    count: int = 1
    window: int = 60
    distinct: str | None = None
    field: str | None = None
    transform: str | None = None
    steps: list[dict] = listfield(default_factory=list)
    join: list[str] = listfield(default_factory=list)
    cooldown: int = 60
    budget: float = 1.0
    examples: dict = listfield(default_factory=dict)
    path: str = ""

    @classmethod
    def parse(cls, doc: dict, allow: dict, path: str = "") -> Rule:
        missing = {"id", "title", "severity", "technique", "kind", "source"} - set(doc)
        if missing:
            raise ValueError(f"{path}: missing {sorted(missing)}")
        if doc["kind"] not in KINDS or doc["severity"] not in SEVERITY:
            raise ValueError(f"{path}: kind {doc['kind']} or severity {doc['severity']} unknown")
        sub = lambda w: _substitute(w or {}, allow)  # noqa: E731
        return cls(
            doc["id"],
            doc["title"],
            doc["severity"],
            doc["technique"],
            doc["kind"],
            doc["source"],
            sub(doc.get("where")),
            doc.get("by", "person"),
            doc.get("count", 1),
            doc.get("window_min", 60),
            doc.get("distinct"),
            doc.get("field"),
            doc.get("transform"),
            [{**s, "where": sub(s.get("where"))} for s in doc.get("steps", [])],
            doc.get("join", []),
            doc.get("cooldown_min", 60),
            doc.get("budget_per_day", 1.0),
            doc.get("examples", {}),
            path,
        )


def _substitute(where: dict, allow: dict) -> dict:
    """Lists named with a $ come from config/platform.toml [allow], so the allowlists live in one place."""
    out = {}
    for k, cond in where.items():
        if isinstance(cond, dict):
            cond = {op: (allow[v[1:]] if isinstance(v, str) and v.startswith("$") else v) for op, v in cond.items()}
        out[k] = cond
    return out


def load_rules(folder: str | Path | None = None) -> list[Rule]:
    cfg = load("platform")
    folder = ROOT / (folder or cfg["detect"]["rules"])
    rules = [Rule.parse(yaml.safe_load(p.read_text()), cfg["allow"], str(p.relative_to(ROOT))) for p in sorted(folder.glob("*.yaml"))]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("two detections share an id")
    return rules


def _op(op: str, arg, v) -> bool:
    s = "" if v is None else str(v)
    if op == "in":
        return v in arg
    if op == "not_in":
        return v not in arg
    if op == "contains":
        return arg in s
    if op == "regex":
        return re.search(arg, s) is not None
    if op == "prefix_in":
        return any(s.startswith(a) for a in arg)
    if op == "not_prefix_in":
        return not any(s.startswith(a) for a in arg)
    if op == "contains_any":
        return any(a in s for a in arg)
    if op == "gt":
        return v is not None and v > arg
    if op == "ne":
        return v != arg
    raise ValueError(f"unknown operator {op}")


def holds(cond, v) -> bool:
    if not isinstance(cond, dict):
        return v == cond
    return all(_op(op, arg, v) for op, arg in cond.items())


def matches(where: dict, e: dict) -> bool:
    return all(holds(cond, e.get(k)) for k, cond in where.items())


def transform(v, how: str | None):
    if how == "ip16" and v:
        try:
            return str(ipaddress.ip_network(f"{v}/16", strict=False))
        except ValueError:
            return v
    return v


@dataclass
class Alert:
    id: str
    rule: str
    severity: str
    technique: str
    entity: str
    ts: int
    eids: list[str]


class Engine:
    """Runs a set of detections over events in time order. `key` names the entity an event belongs to: the person from
    the context graph, or the raw identifier a SIEM without one would use."""

    def __init__(
        self,
        rules: list[Rule],
        key: Callable[[dict], str | None],
        learn_until: int = 0,
        evidence: int = 50,
        enrich: Callable[[dict], dict] | None = None,
    ):
        self.rules, self.key, self.learn_until, self.evidence, self.enrich = rules, key, learn_until, evidence, enrich
        self.by_source: dict[str, list[Rule]] = defaultdict(list)
        for r in rules:
            self.by_source[r.source].append(r)
        self.windows: dict = defaultdict(deque)
        self.seen: dict = defaultdict(set)
        self.progress: dict = {}
        self.last: dict[tuple, int] = {}
        self.alerts: list[Alert] = []
        self.suppressed: dict[str, int] = defaultdict(int)

    def run(self, events: Iterable[dict]) -> list[Alert]:
        for e in events:
            rules = self.by_source.get(e["src"])
            if not rules:
                continue
            if self.enrich:  # what the context graph adds: the person behind the event, their status, whose device it is
                e = {**e, **self.enrich(e)}
            for r in rules:
                self._step(r, e)
        return self.alerts

    def _entity(self, r: Rule, e: dict) -> str | None:
        return self.key(e) if r.by == "person" else str(e.get(r.by))

    def _fire(self, r: Rule, ent: str, e: dict, eids: list[str]) -> None:
        k = (r.id, ent)
        if k in self.last and e["ts"] - self.last[k] < r.cooldown:  # the same detection on the same entity is quiet for a while
            self.suppressed[r.id] += 1
            return
        self.last[k] = e["ts"]
        self.alerts.append(Alert(f"{r.id}:{e['eid']}", r.id, r.severity, r.technique, ent, e["ts"], list(dict.fromkeys(eids))[-self.evidence :]))

    def _step(self, r: Rule, e: dict) -> None:
        if r.kind != "sequence" and not matches(r.where, e):
            return
        ent = self._entity(r, e)
        if ent is None:
            return
        if r.kind == "match":
            self._fire(r, ent, e, [e["eid"]])
        elif r.kind == "threshold":
            w = self.windows[(r.id, ent)]
            w.append((e["ts"], e["eid"], e.get(r.distinct) if r.distinct else e["eid"]))
            while w and w[0][0] < e["ts"] - r.window:
                w.popleft()
            if len({x[2] for x in w}) >= r.count:
                self._fire(r, ent, e, [x[1] for x in w])
        elif r.kind == "new_value":
            v = transform(e.get(r.field), r.transform)
            seen = self.seen[(r.id, ent)]
            if e["ts"] >= self.learn_until and v not in seen:
                self._fire(r, ent, e, [e["eid"]])
            seen.add(v)
        else:
            self._sequence(r, ent, e)

    def _sequence(self, r: Rule, ent: str, e: dict) -> None:
        join = tuple(e.get(j) for j in r.join)
        k = (r.id, ent, join)
        state = self.progress.setdefault(k, [deque() for _ in r.steps])
        for i in range(len(r.steps) - 1, -1, -1):
            s = r.steps[i]
            if not matches(s["where"], e):
                continue
            for q in state:
                while q and q[0][0] < e["ts"] - r.window:
                    q.popleft()
            if i > 0 and len(state[i - 1]) < r.steps[i - 1].get("count", 1):
                continue
            state[i].append((e["ts"], e["eid"]))
            if i == len(r.steps) - 1 and len(state[i]) >= s.get("count", 1):
                self._fire(r, ent, e, [x[1] for q in state for x in q])
            break


# ----------------------------------------------------------------- the checks a detection passes before it merges
def check_examples(rule: Rule) -> list[str]:
    """Each detection carries events it must fire on and events it must not. A change that breaks one fails CI."""
    problems = []
    for want, cases in (("hit", rule.examples.get("hit", [])), ("miss", rule.examples.get("miss", []))):
        for i, case in enumerate(cases):
            events = []
            for e in case if isinstance(case, list) else [case]:  # `repeat: n` stands for n copies a minute apart
                e = dict(e)
                for _ in range(e.pop("repeat", 1)):
                    events.append(e)
            evs = [{"eid": f"x-{i}-{j}", "src": rule.source, **e, "ts": e.get("ts", 0) + j} for j, e in enumerate(events)]
            eng = Engine([rule], key=lambda e: "someone", learn_until=0)
            if rule.kind == "new_value":  # the first event is the history, the last one is tested
                eng.learn_until = evs[-1]["ts"]
            fired = bool(eng.run(evs))
            if fired != (want == "hit"):
                problems.append(f"{rule.id}: {want} example {i} {'did not fire' if want == 'hit' else 'fired'}")
    if not rule.examples.get("hit"):
        problems.append(f"{rule.id}: no example it must fire on")
    if not rule.examples.get("miss"):
        problems.append(f"{rule.id}: no example it must stay quiet on")
    return problems


def backtest(
    rules: list[Rule],
    events: list[dict],
    key: Callable[[dict], str | None],
    learn_days: int,
    test_days: int,
    enrich: Callable[[dict], dict] | None = None,
) -> dict[str, dict]:
    """Replay each detection on history with no known attack: learn on the first days, count alerts on the rest. Every
    alert there is a false positive the queue would have to read."""
    start, end = learn_days * DAY, (learn_days + test_days) * DAY
    eng = Engine(rules, key, learn_until=start, enrich=enrich)
    eng.run(e for e in events if e["ts"] < end)
    out = {}
    for r in rules:
        n = sum(1 for a in eng.alerts if a.rule == r.id and a.ts >= start)
        out[r.id] = {"alerts": n, "per_day": round(n / test_days, 2), "budget": r.budget, "within": n / test_days <= r.budget}
    return out
