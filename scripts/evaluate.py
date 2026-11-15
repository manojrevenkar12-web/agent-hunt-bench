"""Run every design on the same simulated environment and score it against the truth the environment kept.

    python scripts/evaluate.py              the dev environment, writes reports/dev.json
    python scripts/evaluate.py --heldout    the held-out environment, once (config/heldout.lock records it)

This is the only script that imports the world."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from huntbench.detect import Engine, backtest, check_examples, load_rules
from huntbench.graph import Graph, raw_key
from huntbench.pipeline import run
from huntbench.settings import load
from huntbench.triage import check_claims
from huntbench.world.sim import ATTACK_TECH, DAY, WORK_LEN, WORK_START, World

DESIGNS = ["siem_basic", "detection_as_code", "llm_triage", "platform"]


def design_run(name: str, w: World, cfg: dict, index: dict) -> dict:
    d = cfg["designs"][name]
    learn = cfg["detect"]["learn_days"] * DAY
    graph = Graph.build(w.directory(), w.inventory(), w.agents()).learn(w.events, learn) if d["graph"] else None
    rules = load_rules(cfg["detect"]["rules"] if d["rules"] == "team" else cfg["detect"]["vendor_rules"])
    eng = Engine(rules, graph.resolve if graph else raw_key, learn_until=learn, enrich=graph.enrich if graph else None)
    alerts = [a for a in eng.run(w.events) if a.ts >= learn]
    model = lambda key, packet, ctx: w.triage(key, [e["eid"] for e in packet["events"]], ctx)  # noqa: E731
    out = run(d, cfg, alerts, index, graph, model, w.person_reads)
    return {"design": d, "graph": graph, "rules": rules, "alerts": alerts, "out": out, "suppressed": dict(eng.suppressed)}


def score(name: str, r: dict, w: World) -> dict:
    out, alerts = r["out"], r["alerts"]
    eval_days = w.cfg["days"] - w.cfg["baseline_days"]
    camp_events = defaultdict(set)
    for eid, (cid, _) in w.truth.items():
        camp_events[cid].add(eid)
    case_eids = {c.id: set(c.eids) for c in out.cases}
    alert_by_id = {a.id: a for a in alerts}
    rows = []
    for c in w.campaigns:
        ev = camp_events[c.id]
        hits = [a for a in alerts if ev & set(a.eids)]
        first = min((a.ts for a in hits), default=None)
        caught = [i.handled_at for i in out.items if i.verdict == "incident" and ev & case_eids[i.case]]
        held = [ts for aid, ts, _ in out.holds if ev & set(alert_by_id[aid].eids)]
        prevented = bool(held) and min(held) <= c.impact_at
        caught_at = min(caught) if caught else None
        closed = sum(1 for aid, _, eids in out.closed_by_model if ev & set(eids) and ev & set(alert_by_id[aid].eids))
        rows.append(
            {
                "campaign": c.id,
                "kind": c.kind,
                "variant": c.variant,
                "detected": first is not None,
                "minutes_to_detect": None if first is None else first - c.start,
                "caught": caught_at is not None or prevented,
                "minutes_to_person": None if caught_at is None else caught_at - c.start,
                "impact_minutes": c.impact_at - c.start,
                "prevented_by_hold": prevented,
                "before_impact": prevented or (caught_at is not None and caught_at <= c.impact_at),
                "attack_alerts_closed_by_model": closed,
                "stages_seen": sorted({w.truth[e][1] for a in hits for e in a.eids if e in w.truth and w.truth[e][0] == c.id}),
            }
        )
    items = out.items
    attack_items = [i for i in items if w.attack_of(sorted(case_eids[i.case]))]
    night = [i for i in items if i.page and not (WORK_START <= i.ts % DAY < WORK_START + WORK_LEN)]
    benign_holds = [h for h in out.holds if not w.attack_of(alert_by_id[h[0]].eids)]
    mins = [x["minutes_to_person"] for x in rows if x["minutes_to_person"] is not None]
    return {
        "name": name,
        "campaigns": rows,
        "detected": sum(x["detected"] for x in rows),
        "caught": sum(x["caught"] for x in rows),
        "before_impact": sum(x["before_impact"] for x in rows),
        "median_minutes_to_person": float(np.median(mins)) if mins else None,
        "alerts": len(alerts),
        "alerts_per_day": round(len(alerts) / eval_days, 1),
        "cases_per_day": round(len(out.cases) / eval_days, 1),
        "items_per_day": round(len(items) / eval_days, 1),
        "pages_per_day": round(sum(i.page for i in items) / eval_days, 2),
        "night_pages": len(night),
        "precision": round(len(attack_items) / len(items), 3) if items else None,
        "analyst_hours_per_day": round(len(items) * w.cfg["analysts"]["minutes_per_alert"] / 60 / eval_days, 1),
        "reports": out.reports,
        "failed_checks": out.failed_checks,
        "unsupported_claims_relied_on": out.unsupported_shown,
        "closed_on_unsupported_report": out.closed_on_unsupported,
        "closed_by_model": len(out.closed_by_model),
        "attack_alerts_closed_by_model": sum(x["attack_alerts_closed_by_model"] for x in rows),
        "holds": len(out.holds),
        "benign_holds": len(benign_holds),
        "playbook_steps": dict(Counter(s.action for _, steps in out.contained.values() for s in steps)),
    }


def paired(a: list[bool], b: list[bool], seed: str, n: int = 4000) -> dict:
    """Bootstrap over campaigns, both designs scored on the same draw of campaigns."""
    x = np.array(a, float) - np.array(b, float)
    g = np.random.default_rng(int(hashlib.blake2b(seed.encode(), digest_size=8).hexdigest(), 16))
    boots = x[g.integers(0, len(x), (n, len(x)))].mean(1)
    return {
        "difference": round(float(x.mean()), 3),
        "low": round(float(np.quantile(boots, 0.05)), 3),
        "high": round(float(np.quantile(boots, 0.95)), 3),
    }


def detections_table(runs: dict, w: World, cfg: dict) -> list[dict]:
    r = runs["platform"]
    graph = r["graph"]
    bt = backtest(r["rules"], w.events, graph.resolve, cfg["backtest"]["learn_days"], cfg["backtest"]["test_days"], enrich=graph.enrich)
    rows = []
    for rule in r["rules"]:
        mine = [a for a in r["alerts"] if a.rule == rule.id]
        true = [a for a in mine if w.attack_of(a.eids)]
        rows.append(
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "technique": rule.technique,
                "kind": rule.kind,
                "source": rule.source,
                "alerts": len(mine),
                "true": len(true),
                "precision": round(len(true) / len(mine), 2) if mine else None,
                "campaigns": len({w.attack_of(a.eids) for a in true}),
                "backtest_per_day": bt[rule.id]["per_day"],
                "budget": rule.budget,
                "within_budget": bt[rule.id]["within"],
                "examples_pass": not check_examples(rule),
            }
        )
    return rows


def coverage(runs: dict, w: World) -> list[dict]:
    """For each attack and stage, which designs saw it at all."""
    seen = {}
    for name, r in runs.items():
        for a in r["alerts"]:
            for e in a.eids:
                if e in w.truth:
                    cid, stage = w.truth[e]
                    seen.setdefault((cid.rsplit("-", 1)[0], stage), set()).add(name)
    return [
        {"kind": kind, "stage": stage, "technique": tech, "designs": sorted(seen.get((kind, stage), set()), key=DESIGNS.index)}
        for kind, stages in ATTACK_TECH.items()
        for stage, tech in stages.items()
    ]


def graph_stats(w: World, graph: Graph) -> dict:
    resolved = Counter()
    total = Counter()
    keys = defaultdict(set)
    for e in w.events:
        total[e["src"]] += 1
        who = graph.resolve(e)
        if who:
            resolved[e["src"]] += 1
            keys[who].add(raw_key(e))
    renamed = [p for p in w.people if p.serial and p.edr_host != p.hostname]
    learned = sum(graph.device_owner(p.edr_host) == p.email for p in renamed)
    return {
        "events_resolved": {s: round(resolved[s] / total[s], 4) for s in sorted(total)},
        "identifiers_per_person": round(float(np.mean([len(v) for v in keys.values()])), 1),
        "renamed_hosts": len(renamed),
        "renamed_hosts_owner_learned": learned,
    }


def example_case(runs: dict, w: World, index: dict) -> dict:
    """The platform's case for the first account takeover, as the console shows it."""
    r = runs["platform"]
    out = r["out"]
    camp = next(c for c in w.campaigns if c.kind == "account_takeover")
    ev = {e for e, (cid, _) in w.truth.items() if cid == camp.id}
    case = next(c for c in out.cases if ev & set(c.eids))
    packet_events = [index[e] for e in case.eids[-cfg_evidence(r) :]]
    report = w.triage(case.alerts[0].id, [e["eid"] for e in packet_events], True)
    check = check_claims(report, index, [e["eid"] for e in packet_events])
    item = next((i for i in out.items if i.case == case.id), None)
    steps = out.contained.get(case.id, (None, []))[1]
    return {
        "campaign": camp.id,
        "case": case.id,
        "start": camp.start,
        "impact_at": camp.impact_at,
        "alerts": [{"rule": a.rule, "severity": a.severity, "technique": a.technique, "ts": a.ts, "events": len(a.eids)} for a in case.alerts],
        "report": {"escalate": report["escalate"], "claims": report["claims"], "check_ok": check.ok, "problems": check.problems},
        "person": {"reason": item.reason, "page": item.page, "handled_at": item.handled_at, "verdict": item.verdict} if item else None,
        "playbook": [{"action": s.action, "system": s.system, "target": s.target, "status": "dry-run"} for s in steps],
    }


def cfg_evidence(r: dict) -> int:
    return load("platform")["triage"]["evidence_events"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--heldout", action="store_true")
    args = ap.parse_args()
    name = "heldout" if args.heldout else "world"
    lock = ROOT / "config" / "heldout.lock"
    if args.heldout and lock.exists():
        sys.exit(f"the held-out environment was already run ({lock.read_text().strip()}); fix on dev and do not run it again")
    t0 = time.time()
    w = World.load(name)
    cfg = load("platform")
    index = w.index()
    runs = {d: design_run(d, w, cfg, index) for d in DESIGNS}
    scores = {d: score(d, runs[d], w) for d in DESIGNS}
    before = {d: [x["before_impact"] for x in scores[d]["campaigns"]] for d in DESIGNS}
    report = {
        "environment": {
            "name": w.cfg["name"],
            "people": len(w.people),
            "days": w.cfg["days"],
            "evaluated_days": w.cfg["days"] - w.cfg["baseline_days"],
            "events": len(w.events),
            "campaigns": len(w.campaigns),
            "quiet_variants": sum(c.variant for c in w.campaigns),
            "events_by_source": dict(Counter(e["src"] for e in w.events)),
        },
        "designs": scores,
        "paired_before_impact": {f"platform_vs_{d}": paired(before["platform"], before[d], f"{name}-{d}") for d in DESIGNS if d != "platform"},
        "detections": detections_table(runs, w, cfg),
        "coverage": coverage(runs, w),
        "graph": graph_stats(w, runs["platform"]["graph"]),
        "example_case": example_case(runs, w, index),
        "seconds": round(time.time() - t0, 1),
    }
    report.pop("seconds")
    path = ROOT / "reports" / ("heldout.json" if args.heldout else "dev.json")
    path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    if args.heldout:
        lock.write_text(f"run {time.strftime('%Y-%m-%d')}; seed {w.cfg['seed']}\n")
    for d in DESIGNS:
        s = scores[d]
        print(
            f"{d:18} caught {s['caught']:2}/{len(w.campaigns)} before impact {s['before_impact']:2} items/day {s['items_per_day']:5} "
            f"pages/day {s['pages_per_day']:4} precision {s['precision']} model closed attack alerts {s['attack_alerts_closed_by_model']} "
            f"unsupported relied on {s['unsupported_claims_relied_on']}/{s['closed_on_unsupported_report']} median min {s['median_minutes_to_person']}"
        )
    print(f"{time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
