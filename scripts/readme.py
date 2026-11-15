"""Write README.md and web/public/data/console.json from reports/dev.json (and reports/heldout.json once it exists)."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/manojrevenkar12-web/agent-hunt-bench"
NAMES = {
    "siem_basic": "SIEM defaults, every alert to a person",
    "detection_as_code": "Reviewed, backtested detections on the context graph",
    "llm_triage": "+ a model closes alerts it reads on their own",
    "platform": "+ cases, context, checked claims, held agent sends",
}
KINDS = {
    "account_takeover": "Account takeover",
    "insider_exfil": "Insider leaving with data",
    "oauth_consent": "Consent phishing app",
    "agent_injection": "Prompt injection of a productivity agent",
    "cloud_key_abuse": "Leaked CI key",
    "endpoint_intrusion": "Laptop intrusion to ransomware",
}


def pct(x, d=0):
    return f"{x * 100:.{d}f}%"


def table(head, rows, left=1):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * left + ["--:"] * (len(head) - left)) + "|"]
    return "\n".join(out + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def mins(x):
    if x is None:
        return "–"
    return f"{x / 60:.1f} h" if x >= 120 else f"{x:.0f} min"


def design_table(r):
    n = r["environment"]["campaigns"]
    rows = []
    for k, name in NAMES.items():
        d = r["designs"][k]
        rows.append(
            [
                f"**{name}**" if k == "platform" else name,
                f"{d['caught']} of {n}",
                f"{d['before_impact']} of {n}",
                mins(d["median_minutes_to_person"]),
                d["items_per_day"],
                d["pages_per_day"],
                pct(d["precision"]) if d["precision"] is not None else "–",
                d["attack_alerts_closed_by_model"],
                d["unsupported_claims_relied_on"] + d["closed_on_unsupported_report"],
            ]
        )
    return table(
        [
            "Design",
            "Caught",
            "Stopped before impact",
            "Median time to a person",
            "Cases a day for people",
            "Pages a day",
            "Precision",
            "Attack alerts the model closed",
            "Unchecked claims relied on",
        ],
        rows,
    )


def kind_table(r):
    rows = []
    for kind, name in KINDS.items():
        row = [name]
        for k in NAMES:
            cs = [c for c in r["designs"][k]["campaigns"] if c["kind"] == kind]
            row.append(f"{sum(c['before_impact'] for c in cs)}/{len(cs)}")
        cs = [c for c in r["designs"]["platform"]["campaigns"] if c["kind"] == kind]
        row.append(mins(sorted(c["impact_minutes"] for c in cs)[len(cs) // 2]))
        rows.append(row)
    return table(["Attack", "SIEM defaults", "Detection as code", "+ model alone", "Platform", "Median time from first step to impact"], rows)


def detection_rows(r):
    rows = []
    for x in sorted(r["detections"], key=lambda x: (x["source"], x["id"])):
        rows.append(
            [
                f"[`{x['id']}`](detections/rules/{x['id']}.yaml)",
                x["kind"],
                x["source"],
                x["technique"],
                x["severity"],
                x["alerts"],
                x["true"],
                x["campaigns"],
                x["backtest_per_day"],
                x["budget"],
                "pass" if x["within_budget"] and x["examples_pass"] else "**fail**",
            ]
        )
    return table(
        [
            "Detection",
            "Kind",
            "Source",
            "Technique",
            "Severity",
            "Alerts",
            "From attacks",
            "Campaigns",
            "False alerts a day in backtest",
            "Budget",
            "CI",
        ],
        rows,
        left=5,
    )


def coverage_rows(r):
    rows = []
    for c in r["coverage"]:
        rows.append([KINDS[c["kind"]], c["stage"], c["technique"]] + ["✓" if k in c["designs"] else "" for k in NAMES])
    return table(["Attack", "Stage", "Technique", "SIEM defaults", "Detection as code", "+ model alone", "Platform"], rows, left=3)


def example(r):
    e = r["example_case"]
    t0 = e["start"]
    lines = [f"`{e['campaign']}` became `{e['case']}`. Minutes from the attacker's first step:", ""]
    steps, seen = [], set()
    for a in e["alerts"]:
        if a["rule"] not in seen:
            seen.add(a["rule"])
            n = a["events"]
            steps.append((a["ts"], f"`{a['rule']}` fires ({a['severity']}, {a['technique']}) on {n} event{'s' if n != 1 else ''}"))
    p = e["person"]
    if p:
        how = "is paged" if p["page"] else "takes it from the queue"
        steps.append(
            (
                p["handled_at"],
                f"a person {how} ({p['reason']}) and "
                + ("confirms an incident; containment is planned" if p["verdict"] == "incident" else "closes it"),
            )
        )
    steps.append((e["impact_at"], "the bulk export the attacker was working towards"))
    lines += [f"- **{ts - t0} min** {text}" for ts, text in sorted(steps, key=lambda x: x[0])]
    rep = e["report"]
    lines += [
        "",
        f"The model's report cited {len(rep['claims'])} events; the checker found "
        + ("every claim in the evidence." if rep["check_ok"] else "; ".join(rep["problems"]) + "."),
        "",
        "Containment planned at confirmation, in dry run: " + ", ".join(f"`{s['action']}` on {s['system']}" for s in e["playbook"]) + ".",
    ]
    return "\n".join(lines)


def held_section(h, r):
    if not h:
        return "Not run yet. `python scripts/evaluate.py --heldout` runs it once and writes `config/heldout.lock`."
    n = h["environment"]["campaigns"]
    rows = []
    for k, name in NAMES.items():
        d, dv = h["designs"][k], r["designs"][k]
        rows.append(
            [
                name,
                f"{d['caught']} of {n}",
                f"{d['before_impact']} of {n} (dev {dv['before_impact']})",
                d["items_per_day"],
                d["attack_alerts_closed_by_model"],
                d["unsupported_claims_relied_on"] + d["closed_on_unsupported_report"],
            ]
        )
    missed = [c for c in h["designs"]["platform"]["campaigns"] if not c["before_impact"]]
    env = h["environment"]
    return f"""Run once, with the code and settings the dev environment ended on (`config/heldout.lock`): {env["people"]} people, more
contractors and renamed laptops, {env["quiet_variants"]} of {n} campaigns in their quiet variant, and a model that fabricates more.

{table(["Design", "Caught", "Stopped before impact", "Cases a day", "Attack alerts the model closed", "Unchecked claims relied on"], rows)}

The platform did not stop {len(missed)} campaign{"s" if len(missed) != 1 else ""} before impact: {", ".join(f"`{c['campaign']}`" for c in missed) or "none"}.
What that showed and what changed on dev afterwards is in [docs/heldout.md](docs/heldout.md). `config/gate.toml` was not moved."""


def readme(r, h):
    env, d = r["environment"], r["designs"]
    p, dac, llm, siem = d["platform"], d["detection_as_code"], d["llm_triage"], d["siem_basic"]
    pb = r["paired_before_impact"]
    g = r["graph"]
    n = env["campaigns"]
    return f"""# agent-hunt-bench

Detection and response for a SaaS company, measured against attacks whose truth is known: detections written as code
and backtested before they merge, a context graph that joins five log sources into one person, a language model that
triages cases but whose every claim is checked by code, and containment playbooks that run dry until a person approves.

Public write-ups of agentic threat hunters describe these parts (a precomputed context graph, a deterministic claim
checker, an agent that opens detection merge requests) without accuracy numbers. This repository puts numbers on them:
a simulated company of {env["people"]} people over {env["days"]} days, {env["events"]:,} events from identity, documents, productivity agents,
cloud and endpoints, and {n} attack campaigns of six kinds, {env["quiet_variants"]} of them in a quieter variant. The simulation keeps the
truth; the detections, the graph and the routing never see it.

![console](docs/console.png)

## Dashboard

{design_table(r)}

The full platform stopped **{p["before_impact"]} of {n}** campaigns before impact while asking people to read **{p["items_per_day"]} cases a day**,
against {dac["before_impact"]} of {n} and {dac["items_per_day"]} a day when every reviewed detection goes to a person, and {
        siem["before_impact"]
    } of {n} and {siem["items_per_day"]}
a day on SIEM defaults. On the same campaigns, the gain over detection as code is {
        pct(pb["platform_vs_detection_as_code"]["difference"], 1)
    } of campaigns
(90% interval {pct(pb["platform_vs_detection_as_code"]["low"], 1)} to {pct(pb["platform_vs_detection_as_code"]["high"], 1)}), and over the model alone
{pct(pb["platform_vs_llm_triage"]["difference"], 1)} ({pct(pb["platform_vs_llm_triage"]["low"], 1)} to {
        pct(pb["platform_vs_llm_triage"]["high"], 1)
    }).

Where the gain comes from, by attack:

{kind_table(r)}

- Prompt injection of a productivity agent reaches its impact within minutes of the injected instruction. No queue is
  fast enough; holding the agent's send to a new destination, which is reversible, is the only control that stops it.
- A model reading alerts on their own closed {llm["attack_alerts_closed_by_model"]} alerts from real attacks and relied on
  {
        llm["unsupported_claims_relied_on"] + llm["closed_on_unsupported_report"]
    } claims that cite events that do not exist or misquote them. With the person's context, the code rule that it
  never closes a critical alert, and the claim checker, the platform closed {p["attack_alerts_closed_by_model"]} and relied on {
        p["unsupported_claims_relied_on"] + p["closed_on_unsupported_report"]
    }.
- Reading drops in two steps: {p["alerts_per_day"]} alerts a day group into {p["cases_per_day"]} cases a day on one person each, and the
  model closes most of the benign ones, leaving {p["items_per_day"]} for people.

## The claim checker

The model is assumed to hallucinate. Every report names the events and field values it relies on; code checks each
against the event store before the verdict counts. A report that fails goes to a person whatever it concluded.

{
        table(
            ["", "Reports written", "Failed the check", "Escalations resting on an unsupported claim", "Closures resting on an unsupported claim"],
            [
                ["Model alone", llm["reports"], "not checked", llm["unsupported_claims_relied_on"], llm["closed_on_unsupported_report"]],
                ["Platform", p["reports"], p["failed_checks"], p["unsupported_claims_relied_on"], p["closed_on_unsupported_report"]],
            ],
        )
    }

The checker verifies citations, not reasoning: a report that quotes real events and draws the wrong conclusion passes.
That is why criticals cannot be closed by the model at all.

## Detections

Each detection is a YAML file with its condition, severity, ATT&CK or ATLAS technique, examples it must fire on and
stay quiet on, and a false-positive budget. CI lints every file (`scripts/check_detections.py`); the evaluation replays
each one on a week of attack-free history after a week of learning, and the gate fails any detection over budget.
Two first drafts failed that backtest on dev and one more on the held-out company; each was rewritten, not given a
bigger budget, and its history is in the file's comments.

{detection_rows(r)}

## ATT&CK coverage

Which designs saw each stage of each attack at all, before any routing.

{coverage_rows(r)}

## The context graph

Built from the directory, the device inventory and the agent registry, plus who used each laptop in the learning
weeks. Each person appears under {g["identifiers_per_person"]} different identifiers across the log sources on average.

{table(["Source", "Events resolved to a person"], [[s, pct(v, 2)] for s, v in g["events_resolved"].items()])}

{g["renamed_hosts"]} laptops no longer match the inventory; their owner was learned from history for {g["renamed_hosts_owner_learned"]}. Two
detections exist only because of the graph: an account logging in to a colleague's laptop, and someone serving notice
downloading in volume.

## One case end to end

{example(r)}

## Held-out environment

{held_section(h, r)}

## How it works

```
 logs (idp, documents, agents, cloud, endpoint)      directory, device inventory, agent registry
        │                                                          │
        ▼                                                          ▼
 detection engine ◄── detections/rules/*.yaml           context graph: one person per identity
  match, threshold,      examples + backtest budget            │
  new value, sequence ◄────────────── enrich: person, status, whose device
        │
        ▼
 cases: one person, 24 hours ──► model reads the case with context ──► claim checker
        │                                       │                          │
   agent send to a new destination      escalate / close            failed → a person
   on injected instructions: held               │
        ▼                                       ▼
 page on-call (critical) or queue ──► person confirms ──► playbook, dry run until approved
```

Code decides every route; the model only reads and writes a report. `src/huntbench/pipeline.py` takes the model and
the people as functions, so the evaluation runs it with the simulated ones and production would run it with
`huntbench.llm.AnthropicTriager` and the real queue.

## Run it

```bash
pip install -e ".[dev]"
python -m pytest -q                  # ~3 s
python scripts/check_detections.py   # lint every detection against its examples
python scripts/evaluate.py           # ~7 s, writes reports/dev.json
python scripts/gate.py
python scripts/readme.py             # this file and web/public/data/console.json
cd web && npm ci && npm run dev      # the console
```

## Layout

```
src/huntbench/world/   the simulated company and attackers; holds the truth (evaluation and tests only)
src/huntbench/         detect, graph, cases, triage, pipeline, respond, llm
detections/rules/      the team's detections        detections/vendor/   the SIEM defaults compared against
config/                world, heldout, platform, gate
prompts/triage.md      what the model is shown
scripts/               evaluate, gate, check_detections, readme
web/                   the console (React, Vite, React Query, Framer Motion)
```

## Limits

The environment is simulated, so absolute numbers mean little; the comparison between designs on the same
environment is the point. The model is simulated too, with error rates set in `config/world.toml`; a live run needs
`ANTHROPIC_API_KEY` and replaces only the model function. Analysts are one rate of misses that grows with load.
Containment is planned and never executed here. Repository: {REPO}
"""


def console(r, h):
    keep = {k: r[k] for k in ("environment", "designs", "paired_before_impact", "detections", "coverage", "graph", "example_case")}
    keep["names"], keep["kinds"] = NAMES, KINDS
    keep["heldout"] = None if not h else {k: h[k] for k in ("environment", "designs", "paired_before_impact")}
    return keep


def main():
    r = json.loads((ROOT / "reports" / "dev.json").read_text())
    hp = ROOT / "reports" / "heldout.json"
    h = json.loads(hp.read_text()) if hp.exists() else None
    (ROOT / "README.md").write_text(readme(r, h))
    out = ROOT / "web" / "public" / "data" / "console.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(console(r, h), indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
