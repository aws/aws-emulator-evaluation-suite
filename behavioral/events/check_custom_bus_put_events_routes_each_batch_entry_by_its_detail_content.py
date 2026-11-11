"""custom-bus-put-events-routes-each-batch-entry-by-its-detail-content."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-bus-put-events-routes-each-batch-entry-by-its-detail-content"
GROUP = "telemetry"
SERVICES = ["events"]

DETAIL_TYPE = "sim2real.order-status"
# (marker suffix, detail) per entry of the one PutEvents call; the rule matches level error/fatal
# together with a nested region prefix.
ENTRIES = [
    ("err-eu", {"level": "error", "where": {"region": "eu-frankfurt"}}),
    ("info-eu", {"level": "info", "where": {"region": "eu-dublin"}}),
    ("fatal-eu", {"level": "fatal", "where": {"region": "eu-paris"}}),
    ("err-us", {"level": "error", "where": {"region": "us-virginia"}}),
]
MATCHING = {"err-eu", "fatal-eu"}
PATTERN_DETAIL = {"level": ["error", "fatal"], "where": {"region": [{"prefix": "eu-"}]}}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a custom bus, one four-entry PutEvents is routed entry by entry: the rule matching level
    and a nested region prefix delivers exactly its two entries with their own EventIds, while a
    source-only twin rule receives all four first; after the rule is deleted it is NotFound on that bus.
    """
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-evb-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "EventBusArn"
    ]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus)))
    assert bus_arn.endswith(f":event-bus/{bus}"), (
        f"CreateEventBus returned an ARN for another bus: {bus_arn!r}"
    )

    rule_name = ctx.unique_name("sim2real-evb-rule-")
    control_name = ctx.unique_name("sim2real-evb-ctl-")
    source = ctx.unique_name("sim2real.content.")
    rule_arn = _put_rule(
        ctx,
        events,
        bus,
        rule_name,
        {"source": [source], "detail-type": [DETAIL_TYPE], "detail": PATTERN_DETAIL},
    )
    control_arn = _put_rule(ctx, events, bus, control_name, {"source": [source]})

    queue_url, queue_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)
    control_url, control_queue_arn = _create_queue_with_eventbridge_policy(ctx, control_arn)
    _put_target(ctx, events, bus, rule_name, queue_arn)
    _put_target(ctx, events, bus, control_name, control_queue_arn)

    # Positive control: a warm-up both rules match is re-emitted until both queues hold it, so the
    # graded batch below goes to two live rules.
    warm = _warm_up(ctx, events, bus, source, {queue_url, control_url})

    prefix = ctx.unique_name("m-")
    markers = {suffix: f"{prefix}-{suffix}" for suffix, _ in ENTRIES}
    resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": DETAIL_TYPE,
                "EventBusName": bus,
                "Detail": json.dumps({**detail, "marker": markers[suffix]}),
            }
            for suffix, detail in ENTRIES
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"put_events rejected an entry: {resp}"
    event_ids = {
        suffix: e["EventId"] for (suffix, _), e in zip(ENTRIES, resp["Entries"], strict=True)
    }

    # The twin receives all four, so the bus has dispatched every entry before absence is graded.
    control = _collect(ctx, control_url, set(markers.values()), timeout_s=40.0)
    control.pop(warm, None)
    assert sorted(control) == sorted(markers.values()), (
        f"the twin rule's queue received {sorted(control)}"
    )
    delivered = _collect(ctx, queue_url, {markers[s] for s in MATCHING}, timeout_s=40.0)
    delivered.update(_drain(ctx, queue_url))
    delivered.pop(warm, None)
    want = {markers[s] for s in MATCHING}
    assert set(delivered) == want, (
        f"the content rule delivered {sorted(delivered)}, expected exactly {sorted(want)}"
    )
    for suffix in MATCHING:
        env = delivered[markers[suffix]]
        detail = dict(ENTRIES)[suffix]
        got = (
            env["id"],
            env["source"],
            env["detail-type"],
            env["detail"]["level"],
            env["detail"]["where"],
        )
        assert got == (event_ids[suffix], source, DETAIL_TYPE, detail["level"], detail["where"]), (
            f"entry {suffix} arrived as (id, source, detail-type, level, where) {got!r}"
        )
        assert (env.get("region"), env.get("account")) == (ctx.region, ctx.account), (
            f"entry {suffix} envelope region/account {(env.get('region'), env.get('account'))!r}"
        )

    events.remove_targets(Rule=rule_name, EventBusName=bus, Ids=["sim2real-target"])
    events.delete_rule(Name=rule_name, EventBusName=bus)
    gone = f"Rule {rule_name} does not exist on EventBus {bus}."
    described = _poll_error(
        lambda: events.describe_rule(Name=rule_name, EventBusName=bus), "ResourceNotFoundException"
    )
    _assert_not_found(described, f"DescribeRule on the deleted rule {rule_name}", gone)
    _poll_until(
        lambda: [r["Name"] for r in _list_rules(events, bus, rule_name)],
        lambda n: n == [],
        timeout_s=40.0,
        description=f"deleted rule {rule_name} leaving ListRules",
    )
    put_dead = _error(
        lambda: events.put_targets(
            Rule=rule_name, EventBusName=bus, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}]
        ),
        "ResourceNotFoundException",
        f"PutTargets on the deleted rule {rule_name}",
    )
    _assert_not_found(put_dead, f"PutTargets on the deleted rule {rule_name}", gone)


def _warm_up(ctx, events, bus: str, source: str, queue_urls: set, timeout_s: float = 40.0) -> str:
    """Re-emit an event every rule here matches until each queue in ``queue_urls`` received it;
    return its marker."""
    warm = ctx.unique_name("warm-")
    detail = {"level": "error", "where": {"region": "eu-warm"}, "marker": warm}
    entry = {
        "Source": source,
        "DetailType": DETAIL_TYPE,
        "EventBusName": bus,
        "Detail": json.dumps(detail),
    }
    sqs = ctx.client("sqs")
    pending = set(queue_urls)
    last: dict = {}
    deadline = time.monotonic() + timeout_s
    while pending:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{len(pending)} rule queue(s) never received the warm-up within {timeout_s}s; "
                f"last markers per pending queue {[last.get(u) for u in pending]!r}"
            )
        resp = events.put_events(Entries=[entry])
        assert resp["FailedEntryCount"] == 0, f"put_events rejected the warm-up: {resp}"
        for url in list(pending):
            msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
                "Messages", []
            )
            for msg in msgs:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            last[url] = [_marker_of(json.loads(m["Body"])) for m in msgs]
            if warm in last[url]:
                pending.discard(url)
    return warm


def _error(fn, code: str, what: str) -> dict:
    """The error response of one call failing with ``code``; any other outcome fails."""
    try:
        fn()
    except ClientError as exc:
        got = exc.response["Error"]["Code"]
        assert got == code, f"{what}: expected {code}, got {got!r}"
        return exc.response
    raise AssertionError(f"{what}: expected {code}, the call succeeded")


def _put_rule(ctx, events, bus: str, name: str, pattern: dict) -> str:
    arn = events.put_rule(
        Name=name,
        EventBusName=bus,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: events.delete_rule(Name=name, EventBusName=bus))
    )
    return arn


def _put_target(ctx, events, bus: str, rule: str, target_arn: str) -> None:
    resp = events.put_targets(
        Rule=rule, EventBusName=bus, Targets=[{"Id": "sim2real-target", "Arn": target_arn}]
    )
    assert resp["FailedEntryCount"] == 0, f"put_targets failed: {resp}"
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["sim2real-target"])
        )
    )


def _marker_of(body: dict):
    return body["detail"].get("marker") if isinstance(body.get("detail"), dict) else None


def _collect(ctx, queue_url: str, wanted: set, timeout_s: float) -> dict:
    """Drain until every marker in `wanted` has arrived; return marker -> envelope of all drained."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            seen[_marker_of(body)] = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert wanted <= set(seen), (
        f"queue received {sorted(m for m in seen if m)} within {timeout_s}s, expected {sorted(wanted)}"
    )
    return seen


def _drain(ctx, queue_url: str) -> dict:
    """Receive until one empty long poll; return marker -> envelope of every message drained."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    while True:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        if not msgs:
            return seen
        for msg in msgs:
            body = json.loads(msg["Body"])
            seen[_marker_of(body)] = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-evb-queue-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, queue_arn


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_error(fn, code: str, timeout_s: float = 40.0, interval_s: float = 2.0) -> dict:
    """Poll fn until it fails with `code`; return the error response. Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = "<call succeeded>"
    while time.monotonic() < deadline:
        try:
            fn()
            last = "<call succeeded>"
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            if last == code:
                return exc.response
        time.sleep(interval_s)
    raise AssertionError(f"expected {code}, got {last!r} after {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s: float, description: str, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _assert_not_found(response: dict, what: str, message: str) -> None:
    """The response is ResourceNotFoundException with exactly ``message`` and an HTTP 4xx."""
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, (
        f"{what} carried HTTP {status!r}, expected 4xx"
    )
    got = (response["Error"].get("Code"), response["Error"].get("Message"))
    assert got == ("ResourceNotFoundException", message), (
        f"{what}: expected ('ResourceNotFoundException', {message!r}), got {got!r}"
    )


def _list_rules(events, bus: str, prefix: str) -> list[dict]:
    rules: list[dict] = []
    for page in events.get_paginator("list_rules").paginate(NamePrefix=prefix, EventBusName=bus):
        rules.extend(page.get("Rules", []))
    return rules


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
