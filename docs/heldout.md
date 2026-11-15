# Held-out run

Run once on 15 November 2026 with the code, detections and settings the dev environment ended on (commit `9a9348f`),
recorded in `config/heldout.lock`. The held-out company has 420 people instead of 300, twice the share of contractors,
26 laptops renamed since the inventory instead of 11, 10 of 24 campaigns in their quiet variant instead of 5, and a
model that fabricates claims a third more often. `config/gate.toml` was not moved.

## What it showed

| Design | Caught | Stopped before impact | Cases a day | Attack alerts the model closed | Unchecked claims relied on |
|---|--:|--:|--:|--:|--:|
| SIEM defaults | 17 of 24 | 1 of 24 | 85.4 | 0 | 0 |
| Detection as code | 24 of 24 | 18 of 24 | 11.1 | 0 | 0 |
| + a model alone | 23 of 24 | 16 of 24 | 6.5 | 15 | 18 |
| Platform | 23 of 24 | 23 of 24 | 2.6 | 0 | 0 |

The ordering held: the platform stopped 23 of 24 before impact against 18 for detection as code (paired gain 20.8% of
campaigns, 90% interval 4.2% to 37.5%). The model alone closed every alert of one agent injection and lost it. Two
things went wrong that dev had not shown, and the gate failed on the second.

### 1. A missed page silenced the rest of an intrusion

`endpoint_intrusion-3` raised four alerts on one person: a script piped to a shell from Mail (critical) at minute 0,
the keychain dump (critical) at 20, SSH into a colleague's laptop (high) at 114 and the ransomware rename (critical)
at 196. The on-call engineer was paged for the first and closed it; the simulated analysts miss 4% of real attacks.
The routing then treated the case as dismissed at critical, and every later alert of critical severity or lower as a
repeat. Three detections that would each have paged someone were absorbed into a closed case.

Fixed on dev: a dismissed case stays quiet only for repeats of the detections the person saw when they dismissed it.
A new detection, or a more severe one, goes back to a person. `tests/test_graph_triage.py` reproduces the sequence
(`test_a_missed_page_does_not_silence_the_next_critical`). On dev this changed reading from 2.3 to 2.1 cases a day
and nothing else in the dashboard; dev had no missed page to show the difference.

### 2. A false-positive budget set for 300 people did not hold for 420

`saas_new_download_client` fired whenever someone started using the mobile app or a sync client. Its backtest was
1.0 false alerts a day on dev, at its budget, and 1.29 on the held-out company: the noise grows with headcount and the
budget does not. The gate failed on it.

Fixed on dev: the one attack it had found was by someone serving notice, so it now watches only people the directory
says are leaving, at a budget of 0.2 a day. The budget was not raised to fit.

## Not fixed

Seventeen of the 26 renamed laptops in the held-out company took a name another laptop also uses (first name plus
"-MBP"), so the owner learned from history is ambiguous and was right for 17 of 26. Lateral-movement detection on
those machines depends on that guess. The fix belongs in the data: endpoint agents report a sensor id that the device
inventory can carry, and the graph should join on it instead of the hostname. The simulated endpoint log has no such
field, so this is a limit of the repository, not a setting to tune.

The checker verifies citations, not reasoning. The held-out model fabricated more often and the checker sent 8
reports to a person instead of 5 on dev; it cannot catch a report that quotes real events and concludes wrongly.
