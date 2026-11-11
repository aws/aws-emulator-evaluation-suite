"""events-pattern-language-cidr-matches-addresses-inside-the-block-only."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pattern-language-cidr-matches-addresses-inside-the-block-only"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

RULES = {
    "v4-24": {"detail": {"ip": [{"cidr": "10.0.0.0/24"}]}},
    "v4-31": {"detail": {"ip": [{"cidr": "192.0.2.6/31"}]}},
    "v6-127": {"detail": {"ip": [{"cidr": "2001:db8::/127"}]}},
}
EVENTS = {
    "net-first": {"ip": "10.0.0.0"},
    "net-last": {"ip": "10.0.0.255"},
    "net-next": {"ip": "10.0.1.0"},
    "pair-below": {"ip": "192.0.2.5"},
    "pair-low": {"ip": "192.0.2.6"},
    "pair-high": {"ip": "192.0.2.7"},
    "pair-above": {"ip": "192.0.2.8"},
    "v6-low": {"ip": "2001:db8::"},
    "v6-high": {"ip": "2001:db8::1"},
    "v6-above": {"ip": "2001:db8::2"},
    "not-ip": {"ip": "ten.zero.zero.one"},
    "number": {"ip": 10},
}
# The verdicts real AWS gives, both from TestEventPattern and by live delivery.
# (A /32 or /128 host mask is REFUSED by real AWS -- "IPv4 mask bits must be < 32" -- so the
# narrowest legal blocks are /31 and /127; the refusal is graded by the malformed-pattern check.)
EXPECTED = {
    "v4-24": {"net-first", "net-last"},
    "v4-31": {"pair-low", "pair-high"},
    "v6-127": {"v6-low", "v6-high"},
}


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """cidr matches exactly the addresses inside the block (IPv4 /24 and /31, IPv6 /127) and nothing
    else, a non-address value included, with TestEventPattern agreeing."""
    res = _matrix(ctx, RULES, EVENTS, EXPECTED)
    _assert_matrix(res, EVENTS, EXPECTED)
    edges = {"v4-24": {"net-next"}, "v4-31": {"pair-below", "pair-above"}, "v6-127": {"v6-above"}}
    spill = {r: sorted(c & res["ever"][r]) for r, c in edges.items() if c & res["ever"][r]}
    assert spill == {}, f"an address just outside a block was delivered: {spill!r}"
    junk = sorted(r for r in RULES if {"not-ip", "number"} & res["ever"][r])
    assert junk == [], f"a non-address value matched a cidr rule: {junk!r}"


# One custom bus per check, one rule per pattern row, one SQS queue per rule, and one CONTROL rule
# that matches this check's source alone. Every row's events ride in every PutEvents round, so the
# control queue and each positive-expected row queue act as the differential barrier for that
# row's absences: a non-matching event is only called "not delivered" in a round in which the
# same rule has provably delivered its matching events from the same PutEvents batch.
_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_DETAIL_TYPE = "sim2real.pattern-language"
_ROUND_WINDOW_S = 5.0
_MAX_WARM_ROUNDS = 16
_CONFIRM_BUDGET_S = 90.0
_SETTLE_S = 6.0


def _error_code(call) -> str:
    """Run `call`; return the AWS error code it raised, or '<no error>' if it SUCCEEDED."""
    try:
        call()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "<missing Error.Code>")
    return "<no error>"


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

    Returns evidence only -- the caller asserts. Keys:
      tep[rule][case]      TestEventPattern's verdict for the rule's exact pattern
      confirmed[rule]      cases delivered to the rule's queue in the CONFIRMED round
      ever[rule]           every case the rule's queue received in ANY round
      control              cases the control rule received in the confirmed round
      warm[rule]           True once the rule was seen delivering (live)
      body_errors          delivered envelopes whose content differs from what was put
      put_failures         FailedEntries from PutEvents (should be empty)
    """
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
