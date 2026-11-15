from huntbench.detect import Engine, Rule, backtest, check_examples, holds, load_rules, matches
from huntbench.settings import load

ALLOW = load("platform")["allow"]


def rule(**kw):
    base = {"id": "r", "title": "t", "severity": "high", "technique": "T1078", "kind": "match", "source": "idp", "where": {}}
    return Rule.parse({**base, **kw}, ALLOW)


def ev(i, ts, **f):
    return {"eid": f"idp-{i}", "src": "idp", "ts": ts, **f}


def test_every_detection_passes_its_examples():
    cfg = load("platform")["detect"]
    for r in load_rules(cfg["rules"]) + load_rules(cfg["vendor_rules"]):
        assert not check_examples(r), check_examples(r)


def test_operators():
    assert holds({"in": [1, 2]}, 1) and not holds({"in": [1, 2]}, 3)
    assert holds({"regex": "-ci$"}, "user/a-ci") and not holds({"regex": "-ci$"}, "user/a")
    assert holds({"not_prefix_in": ["10."]}, "91.1.1.1") and not holds({"not_prefix_in": ["10."]}, "10.1.1.1")
    assert holds({"gt": 5}, 6) and not holds({"gt": 5}, None)
    assert matches({"a": 1, "b": {"contains": "x"}}, {"a": 1, "b": "axb"})


def test_allowlists_come_from_config():
    r = rule(where={"app": {"not_in": "$known_apps"}})
    assert r.where["app"]["not_in"] == ALLOW["known_apps"]


def test_threshold_counts_within_the_window_and_then_stays_quiet():
    r = rule(kind="threshold", where={"event": "mfa_deny"}, count=3, window_min=10, cooldown_min=60)
    events = [ev(i, t, event="mfa_deny") for i, t in enumerate([0, 20, 21, 22, 23, 24, 100, 101, 102])]
    alerts = Engine([r], key=lambda e: "p").run(events)
    assert [a.ts for a in alerts] == [22, 102]


def test_distinct_threshold():
    r = rule(kind="threshold", distinct="event_name", count=3, window_min=10, source="cloud")
    same = [{"eid": f"c-{i}", "src": "cloud", "ts": i, "event_name": "List"} for i in range(5)]
    assert not Engine([r], key=lambda e: "p").run(same)
    mixed = [{"eid": f"c-{i}", "src": "cloud", "ts": i, "event_name": n} for i, n in enumerate(["A", "B", "A", "C"])]
    assert len(Engine([r], key=lambda e: "p").run(mixed)) == 1


def test_new_value_learns_first_then_fires_once_per_value():
    r = rule(kind="new_value", field="geo", cooldown_min=0)
    events = [ev(0, 0, geo="DE"), ev(1, 5, geo="NL"), ev(2, 20, geo="DE"), ev(3, 21, geo="BR"), ev(4, 22, geo="BR")]
    alerts = Engine([r], key=lambda e: "p", learn_until=10).run(events)
    assert [a.eids for a in alerts] == [["idp-3"]]


def test_sequence_needs_order_and_the_join():
    r = rule(
        kind="sequence", join=["src_ip"], window_min=30, steps=[{"where": {"event": "mfa_deny"}, "count": 2}, {"where": {"event": "login_success"}}]
    )
    ok = [ev(0, 0, event="mfa_deny", src_ip="a"), ev(1, 1, event="mfa_deny", src_ip="a"), ev(2, 2, event="login_success", src_ip="a")]
    assert len(Engine([r], key=lambda e: "p").run(ok)) == 1
    other_ip = ok[:2] + [ev(2, 2, event="login_success", src_ip="b")]
    assert not Engine([r], key=lambda e: "p").run(other_ip)
    wrong_order = [ev(0, 0, event="login_success", src_ip="a"), ev(1, 1, event="mfa_deny", src_ip="a"), ev(2, 2, event="mfa_deny", src_ip="a")]
    assert not Engine([r], key=lambda e: "p").run(wrong_order)
    too_late = ok[:2] + [ev(2, 90, event="login_success", src_ip="a")]
    assert not Engine([r], key=lambda e: "p").run(too_late)


def test_raw_keys_split_one_person_and_the_graph_joins_them():
    r = rule(kind="threshold", source="idp", where={"event": "x"}, count=2, window_min=60)
    events = [ev(0, 0, event="x", actor_email="a@corp"), ev(1, 1, event="x", actor_email="A-alias")]
    assert not Engine([r], key=lambda e: e["actor_email"]).run(events)
    assert Engine([r], key=lambda e: "a@corp").run(events)


def test_backtest_counts_only_after_learning():
    r = rule(kind="match", where={"event": "x"}, cooldown_min=0, budget_per_day=0.5)
    day = 24 * 60
    events = [ev(i, t, event="x") for i, t in enumerate([10, day + 10, 2 * day + 10, 3 * day + 10])]
    bt = backtest([r], events, key=lambda e: "p", learn_days=2, test_days=2)
    assert bt["r"]["alerts"] == 2 and bt["r"]["per_day"] == 1.0 and not bt["r"]["within"]


def test_a_rule_without_examples_fails_review():
    assert check_examples(rule()) == ["r: no example it must fire on", "r: no example it must stay quiet on"]
