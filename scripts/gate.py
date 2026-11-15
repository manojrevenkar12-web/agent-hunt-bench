"""Fails (exit 1) when a report does not clear config/gate.toml.

python scripts/gate.py                       # reports/dev.json
python scripts/gate.py reports/heldout.json  # read only: the held-out result is a finding, not a release
"""

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(r: dict, g: dict) -> list[str]:
    p, gp, n = r["designs"]["platform"], g["platform"], r["environment"]["campaigns"]
    weeks = r["environment"]["evaluated_days"] / 7
    out = []
    if p["caught"] / n < gp["min_caught"]:
        out.append(f"caught {p['caught']} of {n} campaigns")
    if p["before_impact"] / n < gp["min_before_impact"]:
        out.append(f"stopped {p['before_impact']} of {n} campaigns before impact")
    if p["items_per_day"] > gp["max_items_per_day"]:
        out.append(f"{p['items_per_day']} cases a day for people")
    if p["attack_alerts_closed_by_model"] > gp["max_attack_alerts_closed_by_model"]:
        out.append(f"the model closed {p['attack_alerts_closed_by_model']} alerts from real attacks")
    relied = p["unsupported_claims_relied_on"] + p["closed_on_unsupported_report"]
    if relied > gp["max_unsupported_claims_relied_on"]:
        out.append(f"{relied} unsupported claims relied on")
    if p["benign_holds"] / weeks > gp["max_benign_holds_per_week"]:
        out.append(f"{p['benign_holds']} ordinary agent sends held")
    for d in gp["must_beat"]:
        c = r["paired_before_impact"][f"platform_vs_{d}"]
        if c["low"] <= 0:
            out.append(f"before-impact gain over {d} not clear of zero ({c['low']} to {c['high']})")
    if g["detections"]["all_within_budget"]:
        out += [f"{x['id']} at {x['backtest_per_day']} false alerts a day, budget {x['budget']}" for x in r["detections"] if not x["within_budget"]]
    if g["detections"]["all_examples_pass"]:
        out += [f"{x['id']} fails its own examples" for x in r["detections"] if not x["examples_pass"]]
    return out


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "reports" / "dev.json"
    problems = check(json.loads(path.read_text()), tomllib.loads((ROOT / "config" / "gate.toml").read_text()))
    for x in problems:
        print("GATE:", x)
    if problems:
        sys.exit(1)
    print("Gate passed.")


if __name__ == "__main__":
    main()
