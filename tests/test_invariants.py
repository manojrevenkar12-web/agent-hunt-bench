"""The rules the repository keeps, checked."""

import ast
import json
import re
from pathlib import Path

from huntbench.world.sim import World

ROOT = Path(__file__).resolve().parents[1]


def imports(path: Path) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module:
            out.add(("." * node.level) + node.module)
        elif isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
    return out


def test_only_the_evaluation_imports_the_world():
    for p in list((ROOT / "src" / "huntbench").glob("*.py")) + list((ROOT / "scripts").glob("*.py")):
        if p.name == "evaluate.py":
            continue
        assert not any("world" in m for m in imports(p)), f"{p.name} imports the world"


def test_the_world_does_not_read_the_platforms_settings():
    text = (ROOT / "src" / "huntbench" / "world" / "sim.py").read_text()
    assert "platform" not in text and "gate" not in text and "detections" not in text
    assert not any(
        m.endswith(("detect", "pipeline", "graph", "triage", "cases", "respond")) for m in imports(ROOT / "src" / "huntbench" / "world" / "sim.py")
    )


def test_platform_reads_only_what_the_company_exports():
    """The world's public surface is the logs, the directory, the device inventory and the agent registry."""
    text = (ROOT / "scripts" / "evaluate.py").read_text()
    used = set(re.findall(r"\bw\.(\w+)", text))
    platform_side = {"events", "directory", "inventory", "agents", "index", "triage", "person_reads"}
    truth_side = {"truth", "campaigns", "attack_of", "cfg", "people"}
    assert used <= platform_side | truth_side
    # truth is used only in scoring functions, never passed into the pipeline
    run_call = re.search(r"out = run\((.*)\)", text).group(1)
    assert "truth" not in run_call and "campaigns" not in run_call and "attack_of" not in run_call


def test_same_luck_for_every_design(world: World):
    """The model and the people draw by the alert, never by the design."""
    eids = [e["eid"] for e in world.events[:40]]
    assert world.triage("rule:x", eids, False) == world.triage("rule:x", eids, False)
    assert world.analyst("rule:x", 10_000, 3, False) == world.analyst("rule:x", 10_000, 3, False)
    src = (ROOT / "src" / "huntbench" / "world" / "sim.py").read_text()
    assert "design" not in re.sub(r'""".*?"""', "", src, flags=re.S)


def test_context_never_makes_the_model_worse(world: World):
    """With the same draw, context can only raise escalation of attacks and closure of benign alerts."""
    camp_eids = [e for e, (c, _) in world.truth.items()][:5]
    benign = [e["eid"] for e in world.events if e["eid"] not in world.truth][:5]
    for k in range(300):
        if world.triage(f"a{k}", camp_eids, False)["escalate"]:
            assert world.triage(f"a{k}", camp_eids, True)["escalate"]
        if not world.triage(f"b{k}", benign, False)["escalate"]:
            assert not world.triage(f"b{k}", benign, True)["escalate"]


def test_attacks_start_after_the_learning_period(world: World):
    start = world.cfg["baseline_days"] * 24 * 60
    assert all(c.start >= start for c in world.campaigns)
    assert all(world.events[i]["ts"] <= world.events[i + 1]["ts"] for i in range(len(world.events) - 1))


def test_held_out_lock_matches_the_report():
    lock, held = ROOT / "config" / "heldout.lock", ROOT / "reports" / "heldout.json"
    assert lock.exists() == held.exists()


def test_settings_in_config():
    """Thresholds live in the detection files and config, not in the platform's code."""
    for p in (ROOT / "src" / "huntbench").glob("*.py"):
        text = p.read_text()
        for name in ("gmail.com", "pdf-tools", "collector-relay", "34.", "/Volumes/"):
            assert name not in text, f"{p.name} hard-codes {name}"


def test_reports_are_generated():
    r = json.loads((ROOT / "reports" / "dev.json").read_text())
    readme = (ROOT / "README.md").read_text()
    console = json.loads((ROOT / "web" / "public" / "data" / "console.json").read_text())
    assert f"{r['designs']['platform']['before_impact']} of {r['environment']['campaigns']}" in readme
    assert console["designs"]["platform"]["before_impact"] == r["designs"]["platform"]["before_impact"]
