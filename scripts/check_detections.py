"""Lint every detection without any data: it parses, its operators exist, its allowlists are defined in
config/platform.toml, and it fires on the examples it claims to and stays quiet on the others.

    python scripts/check_detections.py            the team's detections and the vendor defaults
    python scripts/check_detections.py path.yaml  one file, for a pull request

The backtest against attack-free history runs in scripts/evaluate.py and is enforced by scripts/gate.py."""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from huntbench.detect import ATTACK_ID, Rule, check_examples, load_rules
from huntbench.settings import load


def main() -> None:
    problems: list[str] = []
    if len(sys.argv) > 1:
        rules = []
        for p in sys.argv[1:]:
            try:
                rules.append(Rule.parse(yaml.safe_load(Path(p).read_text()), load("platform")["allow"], p))
            except (KeyError, ValueError) as e:
                problems.append(f"{p}: {e}")
    else:
        cfg = load("platform")["detect"]
        rules = load_rules(cfg["rules"]) + load_rules(cfg["vendor_rules"])
    for r in rules:
        problems += check_examples(r)
        if not ATTACK_ID.fullmatch(r.technique):
            problems.append(f"{r.id}: technique {r.technique} is not an ATT&CK or ATLAS id")
        if r.path and Path(r.path).stem != r.id:
            problems.append(f"{r.id}: file name should be {r.id}.yaml")
    for p in problems:
        print("DETECTION:", p)
    if problems:
        sys.exit(1)
    print(f"{len(rules)} detections pass their examples.")


if __name__ == "__main__":
    main()
