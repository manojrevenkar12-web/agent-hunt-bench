"""The committed report holds what the README says about it."""

import json
from pathlib import Path

from gate import check

ROOT = Path(__file__).resolve().parents[1]
R = json.loads((ROOT / "reports" / "dev.json").read_text())
G = __import__("tomllib").loads((ROOT / "config" / "gate.toml").read_text())


def test_dev_report_clears_the_gate():
    assert check(R, G) == []


def test_each_design_adds_something():
    d = R["designs"]
    assert d["detection_as_code"]["caught"] >= d["siem_basic"]["caught"]
    assert d["platform"]["before_impact"] >= d["llm_triage"]["before_impact"] >= d["siem_basic"]["before_impact"]
    assert d["platform"]["items_per_day"] < d["detection_as_code"]["items_per_day"] < d["siem_basic"]["items_per_day"]


def test_the_unchecked_model_relies_on_claims_the_checker_rejects():
    assert R["designs"]["llm_triage"]["unsupported_claims_relied_on"] > 0
    assert R["designs"]["platform"]["unsupported_claims_relied_on"] == 0 and R["designs"]["platform"]["failed_checks"] > 0


def test_the_graph_resolves_every_source():
    assert min(R["graph"]["events_resolved"].values()) > 0.99
    assert R["graph"]["identifiers_per_person"] > 3


def test_gate_catches_a_rule_over_budget():
    bad = json.loads(json.dumps(R))
    bad["detections"][0]["within_budget"] = False
    assert any("budget" in p for p in check(bad, G))
