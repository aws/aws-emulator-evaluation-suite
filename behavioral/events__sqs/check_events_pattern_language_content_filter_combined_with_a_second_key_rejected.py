"""events-pattern-language-content-filter-combined-with-a-second-key-rejected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pattern-language-content-filter-combined-with-a-second-key-rejected"
GROUP = "rule"
SERVICES = ["events", "sqs"]

_REASON = "Event pattern is not valid. Reason: "
# (row, fragment, the exact Reason EventBridge gives, how many characters before the END of the
# submitted pattern the parser reports its column). The refusal quotes the whole submitted pattern,
# so the column is counted back from its end: the tail after this run's source name is fixed.
BAD = [
    ("filter-and-filter", {"detail": {"k": [{"prefix": "a", "suffix": "z"}]}},
     "Only one key allowed in match expression", 5),
    ("filter-and-plain-value", {"detail": {"k": [{"prefix": "a", "abz": 1}]}},
     "Only one key allowed in match expression", 3),
    ("filter-outside-list", {"detail": {"k": {"prefix": "a"}}},
     '"prefix" must be an object or an array', 4),
]


def _refusal(pattern: str, reason: str, back: int) -> str:
    """The exact InvalidEventPatternException message for `pattern`, as real EventBridge words it."""
    return (f'{_REASON}{reason}\n at [Source: (String)"{pattern}"; line: 1, '
            f"column: {len(pattern) - back}]")


# The legal spelling of the same intent: each filter its own list element -- which is an OR.
RULES = {"split": {"detail": {"k": [{"prefix": "a"}, {"suffix": "z"}]}}}
EVENTS = {
    "both": {"k": "abz"},
    "prefix-only": {"k": "ab"},
    "suffix-only": {"k": "xz"},
    "neither": {"k": "xy"},
}
EXPECTED = {"split": {"both", "prefix-only", "suffix-only"}}


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
    """A match expression holds one key: PutRule and TestEventPattern refuse each fragment pairing a
    filter with another filter or value with the exact Reason and leave no rule, while filters as
    separate list elements deliver live as an OR."""
    env = _setup(ctx)
    events = env["events"]
    refused = {}
    for row, frag, reason, back in BAD:
        name = ctx.unique_name(f"{_PREFIX}rule-")
        pattern = json.dumps(_scoped(env, frag))
        # Registered before the call: a target that accepts the bad pattern must not leak the rule.
        ctx.on_cleanup(lambda n=name: _quiet(
            lambda: events.delete_rule(Name=n, EventBusName=env["bus"], Force=True)))
        put = _error(lambda: events.put_rule(Name=name, EventBusName=env["bus"], EventPattern=pattern))
        tep = _error(lambda: _tep(env, _scoped(env, frag), "x", {"k": "abz"}))
        after = _error(lambda: events.describe_rule(Name=name, EventBusName=env["bus"]))
        refused[row] = (name, put, tep, after, _refusal(pattern, reason, back))

    for row, (name, put, tep, after, message) in refused.items():
        assert put == ("InvalidEventPatternException", message), (
            f"{row}: PutRule must refuse this fragment with {message!r}; got {put!r}")
        assert tep == ("InvalidEventPatternException", message), (
            f"{row}: TestEventPattern must refuse the same fragment the same way; got {tep!r}")
        missing = ("ResourceNotFoundException",
                   f"Rule {name} does not exist on EventBus {env['bus']}.")
        assert after == missing, (
            f"{row}: a refused PutRule left rule {name!r} behind: DescribeRule -> {after!r}, "
            f"expected {missing!r}")

    listed, token = [], None
    while True:
        page = events.list_rules(EventBusName=env["bus"], **({"NextToken": token} if token else {}))
        listed += [r["Name"] for r in page.get("Rules", [])]
        token = page.get("NextToken")
        if not token:
            break
    leaked = sorted({v[0] for v in refused.values()} & set(listed))
    assert leaked == [], f"ListRules on this check's own bus shows refused rules: {leaked!r}"

    res = _matrix(ctx, RULES, EVENTS, EXPECTED, env=env)
    _assert_matrix(res, EVENTS, EXPECTED)
    assert res["confirmed"]["split"] == {"both", "prefix-only", "suffix-only"}, (
        f"separate filter elements are an OR: split delivered {sorted(res['confirmed']['split'])!r}")


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
    """Run `call`; return the (code, message) it raised. RAISES if the call succeeds."""
    try:
        resp = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Error.Code>"), err.get("Message", "")
    raise AssertionError(f"the call was expected to be refused but succeeded: {resp!r}")


def _quiet(call) -> None:
    """Teardown: a delete of a rule that was never created is not a verdict."""
    try:
        call()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
