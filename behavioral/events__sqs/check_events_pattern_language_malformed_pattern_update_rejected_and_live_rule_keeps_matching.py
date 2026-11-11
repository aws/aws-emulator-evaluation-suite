"""events-pattern-language-malformed-pattern-update-rejected-and-live-rule-keeps-matching."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pattern-language-malformed-pattern-update-rejected-and-live-rule-keeps-matching"
GROUP = "rule"
SERVICES = ["events", "sqs"]

_REASON = "Event pattern is not valid. Reason: "
# (row, fragment, the exact Reason EventBridge gives). `!=` is not an EventBridge comparator and a
# single-host /32 is not a legal cidr. Every fragment is chosen so that a LENIENT engine applying
# it anyway would start delivering the "zz" event, which the live rule's pattern (prefix "ok")
# never matches.
MALFORMED = [
    ("numeric-not-equal", {"detail": {"n": [{"numeric": ["!=", 1]}]}},
     "Unrecognized numeric range operator: !="),
    ("numeric-string-operand", {"detail": {"n": [{"numeric": [">", "1"]}]}},
     "Value of > must be numeric"),
    ("two-operators", {"detail": {"k": [{"prefix": "z", "suffix": "z"}]}},
     "Only one key allowed in match expression"),
    ("exists-string", {"detail": {"n": [{"exists": "true"}]}},
     "exists match pattern must be either true or false."),
    ("double-star", {"detail": {"k": [{"wildcard": "z**z"}]}},
     "Consecutive wildcard characters at pos 2"),
    ("cidr-host-mask-32", {"detail": {"ip": [{"cidr": "10.0.0.9/32"}]}},
     "IPv4 mask bits must be < 32"),
    ("empty-list", {"detail": {"k": []}},
     "Empty arrays are not allowed"),
    ("single-branch-or", {"$or": [{"detail": {"k": ["zz"]}}]},
     "Unrecognized match type detail"),
    ("unknown-operator", {"detail": {"k": [{"startswith": "z"}]}},
     "Unrecognized match type startswith"),
]
# TestEventPattern refuses every row above with the SAME code and Reason as PutRule -- except this
# one. For a one-branch $or the two validators disagree (deterministically, regardless of key order
# and of create vs update): PutRule says "Unrecognized match type detail",
# TestEventPattern says the $or needs two branches. Both are InvalidEventPatternException.
TEP_REASON = {"single-branch-or": "There must have at least 2 Objects in $or relationship."}
RULES = {"live": {"detail": {"k": [{"prefix": "ok"}]}}}
EVENTS = {
    "ok": {"k": "ok-1", "n": 1, "ip": "192.0.2.1"},
    "zz": {"k": "zz", "n": 5, "ip": "10.0.0.9"},
}
EXPECTED = {"live": {"ok"}}


def _refuse_updates(ctx, env: dict, queues: dict) -> dict:
    """Try every malformed update against the LIVE rule, and one malformed create under a new name."""
    events = env["events"]
    live = queues["live"]
    before = events.describe_rule(Name=live["name"], EventBusName=env["bus"])["EventPattern"]
    out = {"before": before, "rows": {}}
    for row, frag, reason in MALFORMED:
        pattern = json.dumps(_scoped(env, frag))
        code, msg = _error(lambda: events.put_rule(
            Name=live["name"], EventBusName=env["bus"], EventPattern=pattern))
        tep_code, tep_msg = _error(lambda: _tep(env, _scoped(env, frag), "zz", EVENTS["zz"]))
        out["rows"][row] = {"code": code, "msg": msg, "tep_code": tep_code, "tep_msg": tep_msg,
                            "reason": reason, "tep_reason": TEP_REASON.get(row, reason)}
    after = events.describe_rule(Name=live["name"], EventBusName=env["bus"])
    out["after_pattern"], out["after_state"] = after["EventPattern"], after["State"]
    fresh = ctx.unique_name(f"{_PREFIX}rule-")
    fresh_pattern = json.dumps(_scoped(env, MALFORMED[0][1]))
    code, msg = _error(lambda: events.put_rule(
        Name=fresh, EventBusName=env["bus"], EventPattern=fresh_pattern))
    if code == "<no error>":
        ctx.on_cleanup(lambda: events.delete_rule(Name=fresh, EventBusName=env["bus"], Force=True))
    describe_code, describe_message = _error(
        lambda: events.describe_rule(Name=fresh, EventBusName=env["bus"]))
    out["fresh"] = {"name": fresh, "pattern": fresh_pattern, "code": code, "msg": msg,
                    "describe": describe_code,
                    "describe_message": describe_message,
                    "gone": f"Rule {fresh} does not exist on EventBus {env['bus']}."}
    return out


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """PutRule and TestEventPattern refuse nine malformed patterns with exact Reasons, the live
    rule's pattern is unchanged, keeps matching and never delivers "zz", and a malformed create
    leaves no rule."""
    res = _matrix(ctx, RULES, EVENTS, EXPECTED, before_delivery=lambda e, q: _refuse_updates(ctx, e, q))
    hook = res["hook"]
    wrong = {r: (v["code"], v["msg"][:160]) for r, v in hook["rows"].items()
             if v["code"] != "InvalidEventPatternException" or not v["msg"].startswith(_REASON + v["reason"])}
    assert wrong == {}, f"PutRule did not refuse these updates with the exact code and Reason: {wrong!r}"
    tep_wrong = {r: (v["tep_code"], v["tep_msg"][:160]) for r, v in hook["rows"].items()
                 if v["tep_code"] != "InvalidEventPatternException"
                 or not v["tep_msg"].startswith(_REASON + v["tep_reason"])}
    assert tep_wrong == {}, f"TestEventPattern disagreed with PutRule's refusals: {tep_wrong!r}"
    assert hook["after_pattern"] == hook["before"] and hook["after_state"] == "ENABLED", (
        f"a refused update mutated the live rule: before {hook['before']!r} after "
        f"{hook['after_pattern']!r} state {hook['after_state']!r}")
    fresh = hook["fresh"]
    assert fresh["code"] == "InvalidEventPatternException" and fresh["describe"] == "ResourceNotFoundException", (
        f"a malformed create must be refused and leave nothing: {fresh!r}")
    # The message echoes the submitted pattern, then the parser's column, which is not rebuilt.
    echoed = f'{_REASON}{MALFORMED[0][2]}\n at [Source: (String)"{fresh["pattern"]}"; line: 1, column: '
    assert fresh["msg"].startswith(echoed) and fresh["msg"].endswith("]"), (
        f"a malformed create must be refused with the exact Reason: {fresh!r}")
    assert fresh["describe_message"] == fresh["gone"], (
        f"DescribeRule must name the rule the refused create left absent: {fresh!r}")
    _assert_matrix(res, EVENTS, EXPECTED)
    assert "zz" not in res["ever"]["live"] and res["confirmed"]["live"] == {"ok"}, (
        f"after nine refused updates the live rule must still route by prefix 'ok' only: "
        f"ever={sorted(res['ever']['live'])!r} confirmed={sorted(res['confirmed']['live'])!r}")


# One custom bus, one rule and SQS queue per pattern row, and a CONTROL rule matching the source
# alone. A non-matching event counts as "not delivered" only in a round in which the same rule
# delivered its matching events from the same PutEvents batch.
_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_DETAIL_TYPE = "sim2real.pattern-language"
_ROUND_WINDOW_S = 5.0
_MAX_WARM_ROUNDS = 16
_CONFIRM_BUDGET_S = 90.0
_SETTLE_S = 6.0


def _error(call) -> tuple[str, str]:
    """Run `call`; return (code, message) it raised, or ('<no error>', '') if it SUCCEEDED."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Error.Code>"), err.get("Message", "")
    return "<no error>", ""


def _setup(ctx) -> dict:
    """A fresh custom bus and a source only this run can emit. Registers the bus teardown."""
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bus = ctx.unique_name(f"{_PREFIX}bus-")
    bus_arn = events.create_event_bus(
        Name=bus, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    source = ctx.unique_name("sim2real.plang.")
    return {"events": events, "sqs": ctx.client("sqs"), "bus": bus, "bus_arn": bus_arn,
            "source": source, "account": account, "region": ctx.region}


def _scoped(env: dict, fragment: dict) -> dict:
    """A row's matcher, scoped to this run's own source and detail-type."""
    return {"source": [env["source"]], "detail-type": [_DETAIL_TYPE], **fragment}


def _queue(ctx, env: dict) -> dict:
    sqs = env["sqs"]
    url = sqs.create_queue(QueueName=ctx.unique_name(f"{_PREFIX}q-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _rule(ctx, env: dict, pattern: dict) -> dict:
    """Queue + rule (on the check's bus) + queue policy scoped to the rule ARN + target t1."""
    events = env["events"]
    q = _queue(ctx, env)
    name = ctx.unique_name(f"{_PREFIX}rule-")
    rule_arn = events.put_rule(
        Name=name, EventBusName=env["bus"], EventPattern=json.dumps(pattern)
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=env["bus"], Force=True))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "AllowRule", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage", "Resource": q["arn"],
        "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}
    env["sqs"].set_queue_attributes(QueueUrl=q["url"], Attributes={"Policy": json.dumps(policy)})
    resp = events.put_targets(Rule=name, EventBusName=env["bus"],
                              Targets=[{"Id": "t1", "Arn": q["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(
        Rule=name, EventBusName=env["bus"], Ids=["t1"], Force=True))
    assert resp.get("FailedEntryCount", 0) == 0, f"PutTargets failed: {resp.get('FailedEntries')!r}"
    return {"name": name, "arn": rule_arn, "pattern": pattern, **q}


def _detail(case: str, detail: dict, rnd: int) -> dict:
    return {**detail, "_case": case, "_round": rnd}


def _tep(env: dict, pattern: dict, case: str, detail: dict) -> bool:
    event = {"version": "0", "id": "7f3c1a52-0000-4000-8000-000000000000",
             "detail-type": _DETAIL_TYPE, "source": env["source"], "account": env["account"],
             "time": "2026-01-01T00:00:00Z", "region": env["region"], "resources": [],
             "detail": _detail(case, detail, 0)}
    return env["events"].test_event_pattern(
        EventPattern=json.dumps(pattern), Event=json.dumps(event))["Result"]


def _put_round(env: dict, events_table: dict, rnd: int) -> list:
    """One PutEvents round carrying every case. Returns the FailedEntries seen (should be none)."""
    entries = [{"Source": env["source"], "DetailType": _DETAIL_TYPE, "EventBusName": env["bus"],
                "Detail": json.dumps(_detail(case, d, rnd))} for case, d in events_table.items()]
    failed = []
    for i in range(0, len(entries), 10):
        resp = env["events"].put_events(Entries=entries[i:i + 10])
        failed += [e for e in resp.get("Entries", []) if "ErrorCode" in e]
    return failed


def _drain_one(sqs, url: str, window_s: float) -> list:
    out = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = max(0, min(2, int(deadline - time.monotonic())))
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=wait).get("Messages", [])
        for m in msgs:
            try:
                out.append(json.loads(m["Body"]))
            except (ValueError, KeyError):
                out.append({"_unparseable": m.get("Body")})
        if msgs:
            sqs.delete_message_batch(QueueUrl=url, Entries=[
                {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return out


def _drain_all(env: dict, queues: dict, window_s: float) -> dict:
    with ThreadPoolExecutor(max_workers=max(1, len(queues))) as pool:
        futs = {k: pool.submit(_drain_one, env["sqs"], q["url"], window_s) for k, q in queues.items()}
        return {k: f.result() for k, f in futs.items()}


def _matrix(ctx, rules: dict, events_table: dict, expected: dict, env: dict | None = None,
            before_delivery=None) -> dict:
    """Provision every rule row plus a control rule, then deliver every case in rounds.
    Returns evidence only; the caller asserts.
    """
    # Evidence keys:
    #   tep[rule][case]   TestEventPattern's verdict for the rule's exact pattern
    #   confirmed[rule]   cases delivered to the rule's queue in the CONFIRMED round
    #   ever[rule]        every case the rule's queue received in ANY round
    #   control           cases the control rule received in the confirmed round
    #   warm[rule]        True once the rule was seen delivering (live)
    #   body_errors       delivered envelopes whose content differs from what was put
    #   put_failures      FailedEntries from PutEvents (should be empty)
    env = env or _setup(ctx)
    patterns = {r: _scoped(env, frag) for r, frag in rules.items()}
    tep = {r: {c: _tep(env, p, c, d) for c, d in events_table.items()} for r, p in patterns.items()}
    queues = {"__control__": _rule(ctx, env, _scoped(env, {}))}
    for r, p in patterns.items():
        queues[r] = _rule(ctx, env, p)
    hook_result = before_delivery(env, queues) if before_delivery else None

    # (case, round) pairs received per queue, across every round.
    got: dict[str, set] = {k: set() for k in queues}
    body_errors: list = []
    put_failures: list = []

    def absorb(batch: dict) -> None:
        for k, bodies in batch.items():
            for b in bodies:
                det = b.get("detail") if isinstance(b, dict) else None
                if not isinstance(det, dict) or "_case" not in det:
                    body_errors.append({"queue": k, "body": b})
                    continue
                case, rnd = det["_case"], det["_round"]
                got[k].add((case, rnd))
                want = _detail(case, events_table.get(case, {}), rnd)
                env_ok = (b.get("source") == env["source"] and b.get("detail-type") == _DETAIL_TYPE
                          and b.get("account") == env["account"] and b.get("region") == env["region"])
                if det != want or not env_ok:
                    body_errors.append({"queue": k, "sent": want, "delivered": b})

    # The barrier waits on the AUTHORED expectation (real AWS's verdict), never on TEP's.
    expect = {k: set(expected[k]) for k in rules}
    expect["__control__"] = set(events_table)

    def cases_in(k: str, rnd: int) -> set:
        return {c for c, r in got[k] if r == rnd}

    def live(k: str) -> bool:
        rounds = {r for _, r in got[k]}
        return any(expect[k] <= cases_in(k, r) for r in rounds) if expect[k] else True

    rnd = 0
    for rnd in range(1, _MAX_WARM_ROUNDS + 1):
        put_failures += _put_round(env, events_table, rnd)
        absorb(_drain_all(env, queues, _ROUND_WINDOW_S))
        if all(live(k) for k in queues):
            break
    warm = {k: live(k) for k in queues}

    confirm = rnd + 1
    confirmed: dict[str, set] = {k: set() for k in queues}
    if all(warm.values()):
        put_failures += _put_round(env, events_table, confirm)
        deadline = time.monotonic() + _CONFIRM_BUDGET_S
        while time.monotonic() < deadline:
            absorb(_drain_all(env, queues, _ROUND_WINDOW_S))
            if all(expect[k] <= cases_in(k, confirm) for k in queues):
                break
        absorb(_drain_all(env, queues, _SETTLE_S))
        confirmed = {k: cases_in(k, confirm) for k in queues}

    return {
        "env": env, "queues": queues, "tep": tep,
        "confirmed": {k: v for k, v in confirmed.items() if k != "__control__"},
        "ever": {k: {c for c, _ in got[k]} for k in rules},
        "control": confirmed["__control__"],
        "warm": warm, "body_errors": body_errors, "put_failures": put_failures,
        "rounds": confirm, "hook": hook_result,
    }


def _assert_matrix(res: dict, events_table: dict, expected: dict) -> None:
    """The shared agreement assertions: barrier, content, TEP == AWS verdict == live delivery."""
    assert res["put_failures"] == [], f"PutEvents rejected entries: {res['put_failures']!r}"
    cold = sorted(k for k, ok in res["warm"].items() if not ok)
    assert cold == [], (
        f"rules {cold!r} never delivered their matching events within {_MAX_WARM_ROUNDS} rounds, so "
        f"no absence on them is attributable to the matcher; per-rule cases seen: "
        f"{ {k: sorted(v) for k, v in res['ever'].items()} !r}")
    assert res["control"] == set(events_table), (
        f"the control rule (source only) did not receive every case of the confirmed round "
        f"{res['rounds']}: missing {sorted(set(events_table) - res['control'])!r}")
    assert res["body_errors"] == [], (
        f"a delivered envelope differs from the event that was put: {res['body_errors'][:3]!r}")
    tep_wrong = {r: {c: res["tep"][r][c] for c in events_table if res["tep"][r][c] != (c in expected[r])}
                 for r in expected}
    tep_wrong = {r: v for r, v in tep_wrong.items() if v}
    assert tep_wrong == {}, (
        f"TestEventPattern disagreed with the verdicts real AWS returns (rule -> case -> observed): "
        f"{tep_wrong!r}")
    live_wrong = {r: {"expected": sorted(expected[r]), "delivered": sorted(res["confirmed"][r])}
                  for r in expected if res["confirmed"][r] != expected[r]}
    assert live_wrong == {}, f"live delivery disagreed with the expected match set: {live_wrong!r}"
    leaked = {r: sorted(res["ever"][r] - expected[r]) for r in expected if res["ever"][r] - expected[r]}
    assert leaked == {}, (
        f"a rule delivered a non-matching case in SOME round (absence violated): {leaked!r}")
    split = {r: [c for c in events_table if res["tep"][r][c] != (c in res["confirmed"][r])]
             for r in expected}
    split = {r: v for r, v in split.items() if v}
    assert split == {}, (
        f"TestEventPattern and live delivery disagree -- two surfaces of one matcher: {split!r}")
    pos = sum(len(v) for v in expected.values())
    neg = sum(len(events_table) - len(v) for v in expected.values())
    assert pos > 0 and neg > 0 and all(expected.values()), (
        f"the table must keep both directions and a positive per rule: pos={pos} neg={neg} "
        f"{ {r: sorted(v) for r, v in expected.items()} !r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
