"""put-events-triggers-matched-target-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-triggers-matched-target-delivery"
GROUP = "telemetry"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matching PutEvents entry reaches the rule's SQS target with its envelope; a non-matching
    one does not, and once the rule is deleted a matching one does not either. A source-only twin
    rule's queue receiving each event proves the bus dispatched it before absence is graded."""
    events = ctx.client("events")

    rule_name = ctx.unique_name("sim2real-evb-rule-")
    control_name = ctx.unique_name("sim2real-evb-ctl-")
    source = ctx.unique_name("sim2real.matched.")
    detail_type = "sim2real-matched-type"

    rule_arn = _put_rule(ctx, events, rule_name, {"source": [source], "detail-type": [detail_type]})
    assert [r["Name"] for r in _list_rules(events, rule_name)] == [rule_name], (
        f"live rule {rule_name} is not listed by ListRules"
    )
    control_arn = _put_rule(ctx, events, control_name, {"source": [source]})

    queue_url, queue_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)
    control_url, control_queue_arn = _create_queue_with_eventbridge_policy(ctx, control_arn)
    _put_target(ctx, events, rule_name, queue_arn)
    _put_target(ctx, events, control_name, control_queue_arn)

    # A non-matching event (same source, other detail-type) goes first with its own marker.
    other_marker = ctx.unique_name("other-marker-")
    other_resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real-unmatched-type",
                "Detail": json.dumps({"marker": other_marker}),
            }
        ]
    )
    assert other_resp["FailedEntryCount"] == 0, f"put_events rejected the entry: {other_resp}"

    marker = ctx.unique_name("marker-")
    put_resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, f"put_events rejected the entry: {put_resp}"
    event_id = put_resp["Entries"][0]["EventId"]

    envelope = _poll_for_marker(ctx, queue_url, marker, timeout_s=60.0, forbidden=other_marker)
    assert envelope["source"] == source, f"expected source {source!r}, got {envelope['source']!r}"
    assert envelope["detail-type"] == detail_type, (
        f"expected detail-type {detail_type!r}, got {envelope['detail-type']!r}"
    )
    assert envelope["detail"]["marker"] == marker, (
        f"expected marker {marker!r}, got {envelope['detail'].get('marker')!r}"
    )
    assert envelope["id"] == event_id, (
        f"delivered envelope id {envelope['id']!r} does not match PutEvents EventId {event_id!r}"
    )
    assert "time" in envelope, f"delivered envelope has no time field: {sorted(envelope.keys())}"
    assert envelope.get("region") == ctx.region, (
        f"delivered envelope region {envelope.get('region')!r}, expected {ctx.region!r}"
    )
    assert envelope.get("account") == ctx.account, (
        f"delivered envelope account {envelope.get('account')!r}, expected {ctx.account!r}"
    )

    # Twin control: the source-only rule delivers BOTH markers, so the bus has dispatched the
    # non-matching event; only then is the primary queue drained and must not hold it.
    _collect_markers(ctx, control_url, {marker, other_marker}, timeout_s=60.0)
    leftover = _drain(ctx, queue_url)
    assert other_marker not in leftover, (
        f"the non-matching event {other_marker!r} was delivered to the rule's target"
    )
    assert not leftover, f"unexpected extra deliveries to the rule's target: {sorted(leftover)}"

    # The primary rule is deleted and proven gone; a matching event then reaches only the twin.
    events.remove_targets(Rule=rule_name, Ids=["sim2real-target"])
    events.delete_rule(Name=rule_name)
    _assert_rule_gone(events, rule_name, queue_arn)

    after_marker = ctx.unique_name("after-delete-marker-")
    sent = time.monotonic()
    after_resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": after_marker}),
            }
        ]
    )
    assert after_resp["FailedEntryCount"] == 0, f"put_events rejected the entry: {after_resp}"
    _collect_markers(ctx, control_url, {after_marker}, timeout_s=60.0)
    # Absence is graded for at least as long as the twin's delivery took (floor 10 s, cap 60 s).
    window = min(max(time.monotonic() - sent, _ABSENCE_FLOOR_S), _ABSENCE_CAP_S)
    late = _listen(ctx, queue_url, window)
    assert after_marker not in late, (
        f"an event matching the deleted rule {rule_name} was delivered to its former target"
    )
    assert not late, f"unexpected deliveries to the deleted rule's target: {sorted(m for m in late if m)}"

    events.remove_targets(Rule=control_name, Ids=["sim2real-target"])
    events.delete_rule(Name=control_name)
    _assert_rule_gone(events, control_name, control_queue_arn)


#: The fixed bounds of a "nothing arrives" window.
_ABSENCE_FLOOR_S = 10.0
_ABSENCE_CAP_S = 60.0


def _listen(ctx, queue_url: str, window_s: float) -> list:
    """Receive on the queue for the whole window; return the markers of every message seen."""
    sqs = ctx.client("sqs")
    markers = []
    deadline = time.monotonic() + window_s
    while (remaining := deadline - time.monotonic()) > 0:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=max(1, min(5, int(remaining)))
        )
        for msg in resp.get("Messages", []):
            markers.append(_marker_of(json.loads(msg["Body"])))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return markers


def _put_rule(ctx, events, name: str, pattern: dict) -> str:
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_rule(Name=name)))
    return arn


def _put_target(ctx, events, rule: str, target_arn: str) -> None:
    resp = events.put_targets(Rule=rule, Targets=[{"Id": "sim2real-target", "Arn": target_arn}])
    assert resp["FailedEntryCount"] == 0, f"put_targets failed: {resp}"
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: events.remove_targets(Rule=rule, Ids=["sim2real-target"])))
    targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    assert any(t["Arn"] == target_arn for t in targets), f"target was not registered on rule {rule}"


def _assert_rule_gone(events, name: str, target_arn: str) -> None:
    gone = f"Rule {name} does not exist on EventBus default."
    described = _poll_error(lambda: events.describe_rule(Name=name), "ResourceNotFoundException")
    _assert_not_found(described, f"DescribeRule on the deleted rule {name}", gone)
    _poll_until(
        lambda: [r["Name"] for r in _list_rules(events, name)],
        lambda names: names == [], timeout_s=60.0,
        description=f"deleted rule {name} leaving ListRules",
    )
    put_dead = _poll_error(
        lambda: events.put_targets(Rule=name, Targets=[{"Id": "sim2real-target", "Arn": target_arn}]),
        "ResourceNotFoundException",
    )
    _assert_not_found(put_dead, f"PutTargets on the deleted rule {name}", gone)


def _marker_of(body: dict):
    return body["detail"].get("marker") if isinstance(body.get("detail"), dict) else None


def _collect_markers(ctx, queue_url: str, wanted: set, timeout_s: float) -> None:
    """Drain until every marker in `wanted` has arrived on the queue."""
    sqs = ctx.client("sqs")
    seen: set = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= seen:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen.add(_marker_of(json.loads(msg["Body"])))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert wanted <= seen, (
        f"control queue received {sorted(m for m in seen if m)} within {timeout_s}s, "
        f"expected {sorted(wanted)}"
    )


def _drain(ctx, queue_url: str) -> list:
    """Receive until one empty long poll; return the markers of every message drained."""
    sqs = ctx.client("sqs")
    markers = []
    while True:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", [])
        if not msgs:
            return markers
        for msg in msgs:
            markers.append(_marker_of(json.loads(msg["Body"])))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-evb-queue-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
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


def _poll_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 60.0, forbidden: str = "") -> dict:
    """Drain until the envelope carrying `marker` arrives; an envelope carrying `forbidden`
    on the way is a failure."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            got = body["detail"].get("marker") if isinstance(body.get("detail"), dict) else None
            assert not forbidden or got != forbidden, (
                f"the non-matching event {forbidden!r} was delivered to the rule's target: {body!r}"
            )
            if got == marker:
                return body
    raise AssertionError(f"event with marker {marker} was never delivered to {queue_url} within {timeout_s}s")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_error(fn, code: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> dict:
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
    assert isinstance(status, int) and 400 <= status < 500, f"{what} carried HTTP {status!r}, expected 4xx"
    got = (response["Error"].get("Code"), response["Error"].get("Message"))
    assert got == ("ResourceNotFoundException", message), (
        f"{what}: expected ('ResourceNotFoundException', {message!r}), got {got!r}"
    )


def _list_rules(events, prefix: str) -> list[dict]:
    rules: list[dict] = []
    for page in events.get_paginator("list_rules").paginate(NamePrefix=prefix):
        rules.extend(page.get("Rules", []))
    return rules


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
