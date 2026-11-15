# AGENTS.md

How to work in this repository, for people and coding agents.

## Fast feedback

```bash
python -m pytest -q                  # ~3 s
ruff check . && ruff format --check .
python scripts/check_detections.py   # every detection against its own examples
python scripts/evaluate.py           # ~7 s, writes reports/dev.json
python scripts/gate.py
python scripts/readme.py             # README.md and web/public/data/console.json
cd web && npm test && npm run build
```

Commit the regenerated files. CI fails when one does not match its source.

## Invariants

1. **The truth stays in the world.** `src/huntbench/world/` knows which events belong to which attack. Only
   `scripts/evaluate.py` and the tests import it; `tests/test_invariants.py` checks this. The platform reads what a
   company exports: the logs, the directory, the device inventory and the agent registry.
2. **The world does not read the platform's settings.** `config/world.toml` and `config/heldout.toml` drive the
   world; `config/platform.toml` and `detections/` drive the platform.
3. **Same luck for every design.** The model's and the analysts' draws are keyed by the alert, never by the design.
4. **The model reads and code decides.** `src/huntbench/pipeline.py` routes every alert. The model writes a report
   with claims; code checks every claim against the event store, and the model may never close a critical alert.
5. **Log text is data.** Fields in events can be written by an attacker or by content an agent read. The prompt
   fences them and nothing in them is followed.
6. **Nothing acts before a person except a reversible hold.** Playbooks run dry unless an approver is named; the only
   inline action is holding an agent's send, listed in `config/platform.toml [respond] inline_hold`.
7. **Settings in config, results generated.** Thresholds live in the detection files, allowlists in
   `config/platform.toml [allow]`. No number in README.md or the console is typed by hand.

## Held-out rule

`python scripts/evaluate.py --heldout` runs the held-out environment once and writes `config/heldout.lock`. After that,
changes are measured on the dev environment only; findings go in `docs/heldout.md`. `config/gate.toml` is not moved.
