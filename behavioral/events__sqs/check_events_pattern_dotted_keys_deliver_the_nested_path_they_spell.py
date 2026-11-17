"""events-pattern-dotted-keys-deliver-the-nested-path-they-spell."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pattern-dotted-keys-deliver-the-nested-path-they-spell"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

RULES = {'dotted-in-detail': {'detail': {'a.b': ['x']}}, 'dotted-from-top': {'detail.a.b': ['x']}, 'nested': {'detail': {'a': {'b': ['x']}}}}
EVENTS = {'nested': {'a': {'b': 'x'}}, 'literal-dotted': {'a.b': 'x'}, 'array-leaf': {'a': {'b': ['z', 'x']}}, 'other-value': {'a': {'b': 'y'}}, 'shallow': {'a': 'x'}}
EXPECTED = {k: set(v) for k, v in {'dotted-in-detail': ['array-leaf', 'literal-dotted', 'nested'], 'dotted-from-top': ['array-leaf', 'literal-dotted', 'nested'], 'nested': ['array-leaf', 'literal-dotted', 'nested']}.items()}


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A dotted pattern key, inside detail or from the top level, addresses the nested path it spells,
    so it delivers exactly what the nested pattern delivers, a literal dotted event key included."""
    res = _matrix(ctx, RULES, EVENTS, EXPECTED)
    _assert_matrix(res, EVENTS, EXPECTED)
    assert res["confirmed"]["dotted-in-detail"] == res["confirmed"]["nested"] == res["confirmed"]["dotted-from-top"], (
        f"dotted and nested forms of one path delivered different sets: {res['confirmed']!r}")


# One custom bus per check, one rule per pattern row, one SQS queue per rule, and one CONTROL rule
# that matches this check's source alone. Every row's events ride in every PutEvents round, so the
# control queue and each row queue act as the barrier for that row's absences: a non-matching event
# is only called "not delivered" in a round in which the same rule delivered its matching events.
_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_DETAIL_TYPE = "sim2real.pattern-language"
_ROUND_WINDOW_S = 5.0
_MAX_WARM_ROUNDS = 16
_CONFIRM_BUDGET_S = 90.0
_SETTLE_FLOOR_S = 10.0
_SETTLE_FACTOR = 3.0
_SQS_GONE = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _setup(ctx) -> dict:
    """A fresh custom bus and a source only this run can emit. Registers the bus teardown."""
    events = ctx.client("events")
    bus = ctx.unique_name(f"{_PREFIX}bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
    ctx.on_cleanup(_teardown(lambda: events.delete_event_bus(Name=bus), "ResourceNotFoundException"))
    source = ctx.unique_name("sim2real.plang.")
    return {"events": events, "sqs": ctx.client("sqs"), "bus": bus, "source": source,
            "account": ctx.account, "region": ctx.region}


def _scoped(env: dict, fragment: dict) -> dict:
    """A row's matcher, scoped to this run's own source and detail-type."""
    return {**fragment, "source": [env["source"]], "detail-type": [_DETAIL_TYPE]}


def _queue(ctx, env: dict) -> dict:
    sqs = env["sqs"]
    url = sqs.create_queue(QueueName=ctx.unique_name(f"{_PREFIX}q-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_GONE))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _rule(ctx, env: dict, pattern: dict) -> dict:
    """Queue + rule (on the check's bus) + queue policy scoped to the rule ARN + target t1."""
    events = env["events"]
    q = _queue(ctx, env)
    name = ctx.unique_name(f"{_PREFIX}rule-")
    text = json.dumps(pattern)
    rule_arn = events.put_rule(Name=name, EventBusName=env["bus"], EventPattern=text)["RuleArn"]
    ctx.on_cleanup(_teardown(lambda: events.delete_rule(Name=name, EventBusName=env["bus"], Force=True),
                             "ResourceNotFoundException"))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "AllowRule", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage", "Resource": q["arn"],
        "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}
    env["sqs"].set_queue_attributes(QueueUrl=q["url"], Attributes={"Policy": json.dumps(policy)})
    resp = events.put_targets(Rule=name, EventBusName=env["bus"],
                              Targets=[{"Id": "t1", "Arn": q["arn"]}])
    ctx.on_cleanup(_teardown(lambda: events.remove_targets(
        Rule=name, EventBusName=env["bus"], Ids=["t1"], Force=True), "ResourceNotFoundException"))
    assert resp.get("FailedEntryCount", 0) == 0, f"PutTargets failed: {resp.get('FailedEntries')!r}"
    return {"name": name, "arn": rule_arn, "pattern": pattern, "text": text, **q}


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
    """One PutEvents round carrying every case. Returns the FailedEntries seen."""
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
    """Drain every queue in turn, splitting the window between them."""
    share = max(2.0, window_s / max(1, len(queues)))
    return {k: _drain_one(env["sqs"], q["url"], share) for k, q in queues.items()}


def _matrix(ctx, rules: dict, events_table: dict, expected: dict) -> dict:
    """Provision every rule row plus a control rule, then deliver every case in rounds.

    Returns evidence only; the caller asserts.
    """
    env = _setup(ctx)
    patterns = {r: _scoped(env, frag) for r, frag in rules.items()}
    tep = {r: {c: _tep(env, p, c, d) for c, d in events_table.items()} for r, p in patterns.items()}
    queues = {"__control__": _rule(ctx, env, _scoped(env, {}))}
    for r, p in patterns.items():
        queues[r] = _rule(ctx, env, p)

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

    expect = {k: set(expected[k]) for k in rules}
    expect["__control__"] = set(events_table)

    def cases_in(k: str, rnd: int) -> set:
        return {c for c, r in got[k] if r == rnd}

    def live(k: str) -> bool:
        return any(expect[k] <= cases_in(k, r) for r in {r for _, r in got[k]})

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
        sent = time.monotonic()
        put_failures += _put_round(env, events_table, confirm)
        latency = 0.0  # no measurement when the round never completes; the floor applies
        while time.monotonic() < sent + _CONFIRM_BUDGET_S:
            absorb(_drain_all(env, queues, _ROUND_WINDOW_S))
            if all(expect[k] <= cases_in(k, confirm) for k in queues):
                latency = time.monotonic() - sent
                break
        # A late non-matching delivery is watched for max(floor, factor x measured latency).
        settle_until = time.monotonic() + max(_SETTLE_FLOOR_S, _SETTLE_FACTOR * latency)
        while time.monotonic() < settle_until:
            absorb(_drain_all(env, queues, _ROUND_WINDOW_S))
        confirmed = {k: cases_in(k, confirm) for k in queues}

    return {
        "env": env, "queues": queues, "tep": tep,
        "confirmed": {k: v for k, v in confirmed.items() if k != "__control__"},
        "ever": {k: {c for c, _ in got[k]} for k in rules},
        "control": confirmed["__control__"],
        "warm": warm, "body_errors": body_errors, "put_failures": put_failures,
        "rounds": confirm,
    }


def _assert_matrix(res: dict, events_table: dict, expected: dict) -> None:
    """Barrier, content, and TestEventPattern == expected verdict == live delivery."""
    assert res["put_failures"] == [], f"PutEvents rejected entries: {res['put_failures']!r}"
    cold = sorted(k for k, ok in res["warm"].items() if not ok)
    assert cold == [], (
        f"rules {cold!r} never delivered their matching events within {_MAX_WARM_ROUNDS} rounds; "
        f"per-rule cases seen: { {k: sorted(v) for k, v in res['ever'].items()} !r}")
    assert res["control"] == set(events_table), (
        f"the control rule (source only) did not receive every case of round {res['rounds']}: "
        f"missing {sorted(set(events_table) - res['control'])!r}")
    assert res["body_errors"] == [], (
        f"a delivered envelope differs from the event that was put: {res['body_errors'][:3]!r}")
    tep_wrong = {r: {c: res["tep"][r][c] for c in events_table if res["tep"][r][c] != (c in expected[r])}
                 for r in expected}
    tep_wrong = {r: v for r, v in tep_wrong.items() if v}
    assert tep_wrong == {}, f"TestEventPattern verdicts differ (rule -> case -> observed): {tep_wrong!r}"
    live_wrong = {r: {"expected": sorted(expected[r]), "delivered": sorted(res["confirmed"][r])}
                  for r in expected if res["confirmed"][r] != expected[r]}
    assert live_wrong == {}, f"live delivery differs from the expected match set: {live_wrong!r}"
    leaked = {r: sorted(res["ever"][r] - expected[r]) for r in expected if res["ever"][r] - expected[r]}
    assert leaked == {}, f"a rule delivered a non-matching case in some round: {leaked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
