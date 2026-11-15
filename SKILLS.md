# SKILLS.md

## Write a detection

1. Add `detections/rules/<id>.yaml`: `id` (the file name), `title`, `severity`, an ATT&CK or ATLAS `technique`, a
   `kind` (match, threshold, new_value, sequence), the `source`, the condition in `where`, and a `budget_per_day`.
2. Give it `examples`: at least one event list it must fire on (`hit`) and one it must stay quiet on (`miss`). Use
   `repeat: n` for volume, and name allowlists as `$name` from `config/platform.toml [allow]` instead of listing them.
3. `python scripts/check_detections.py detections/rules/<id>.yaml`, then `python scripts/evaluate.py` and
   `python scripts/gate.py`. A detection over its budget on attack-free history fails the gate. Rewrite it; do not
   raise the budget to fit, and leave a comment saying what the first version did.

## Add a log source or a field the graph should know

Resolve it to a person in `Graph.resolve` and give it a raw key in `RAW_KEY`, with a test in
`tests/test_graph_triage.py`. If it carries a new kind of identifier, add the export it comes from to `Graph.build`.

## Change what the model sees

Edit `prompts/triage.md` and `triage.context_packet`. Keep evidence inside the fenced block and keep claims in the
`eid, field, value` form the checker reads. Run the evaluation: the claim-check rows in the README must not move up.

## Run the live model on a case

`pip install -e ".[live]"`, set `ANTHROPIC_API_KEY`, and pass `huntbench.llm.AnthropicTriager()` as the model to
`pipeline.run` (its signature is `model(key, packet, with_context)`; wrap it as `lambda k, p, c: triager(p)`).

## Contain an incident

`respond.plan(case, graph)` lists the calls per log source. `respond.execute(steps, dry_run=False, approver=...)` is
where the systems' clients go; until they are wired in, it only returns the plan marked dry-run.
