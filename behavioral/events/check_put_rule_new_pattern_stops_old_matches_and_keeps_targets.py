"""put-rule-new-pattern-stops-old-matches-and-keeps-targets."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "put-rule-new-pattern-stops-old-matches-and-keeps-targets"
GROUP = "routing"
SERVICES = ["events"]

_DETAIL_TYPE = "sim2real-pattern-swap"
_TARGET_ID = "sim2real-target"


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PutRule with a new EventPattern keeps the rule's ARN and its target, reads back the new
    pattern, delivers an event matching it, and never delivers an event matching only the old pattern."""
    events = ctx.client("events")
    rule = ctx.unique_name("sim2real-evb-swap-")
    src_a = ctx.unique_name("sim2real.swap.a.")
    src_b = ctx.unique_name("sim2real.swap.b.")
    pattern_b = {"source": [src_b], "detail-type": [_DETAIL_TYPE]}

    rule_arn = events.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": [src_a], "detail-type": [_DETAIL_TYPE]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule))
    queue_url, queue_arn = _create_queue_for_rule(ctx, rule_arn, "sim2real-evb-swap-q-")
    resp = events.put_targets(Rule=rule, Targets=[{"Id": _TARGET_ID, "Arn": queue_arn}])
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed: {resp['FailedEntries']!r}"
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=[_TARGET_ID]))

    _converge(ctx, src_a, queue_url, "pattern-a")

    again = events.put_rule(Name=rule, EventPattern=json.dumps(pattern_b), State="ENABLED")
    assert again["RuleArn"] == rule_arn, "the second PutRule on the same name answered a different RuleArn"
    described = events.describe_rule(Name=rule)
    assert json.loads(described["EventPattern"]) == pattern_b, (
        f"DescribeRule after the update reads pattern {described['EventPattern']!r}, expected the B pattern"
    )
    targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    assert [(t["Id"], t["Arn"]) for t in targets] == [(_TARGET_ID, queue_arn)], (
        f"after PutRule replaced the pattern the rule lists {len(targets)} target(s) "
        f"{[t['Id'] for t in targets]!r}; expected exactly the original one"
    )

    _converge(ctx, src_b, queue_url, "pattern-b")

    old = f"old-pattern-{uuid.uuid4().hex}"
    control = f"new-pattern-{uuid.uuid4().hex}"
    resp = events.put_events(
        Entries=[
            {"Source": src_a, "DetailType": _DETAIL_TYPE, "Detail": json.dumps({"marker": old})},
            {"Source": src_b, "DetailType": _DETAIL_TYPE, "Detail": json.dumps({"marker": control})},
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused an entry: {resp['Entries']!r}"
    started = time.monotonic()
    body, seen = _await_marker(ctx, queue_url, control, 120.0)
    assert body is not None, "the event matching the new pattern (positive control) was never delivered"
    assert body["source"] == src_b, "the delivered control event carries a different source than it was put with"
    seen.update(_drain(ctx, queue_url, max(15.0, 3 * (time.monotonic() - started))))
    assert old not in seen, "an event matching only the replaced pattern was still delivered after the update"


def _create_queue_for_rule(ctx, rule_arn: str, prefix: str) -> tuple[str, str]:
    """An SQS queue whose policy lets EventBridge deliver from ``rule_arn`` only."""
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
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


def _put(ctx, source: str, marker: str) -> None:
    resp = ctx.client("events").put_events(
        Entries=[{"Source": source, "DetailType": _DETAIL_TYPE, "Detail": json.dumps({"marker": marker})}]
    )
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused an entry: {resp['Entries']!r}"


def _marker_of(body: dict):
    """The marker of a delivered message: the envelope's detail.marker, or a transformed body's."""
    detail = body.get("detail")
    if isinstance(detail, dict) and "marker" in detail:
        return detail["marker"]
    return body.get("marker")


def _drain(ctx, queue_url: str, window_s: float) -> dict[str, dict]:
    """Receive and delete everything on ``queue_url`` for ``window_s`` seconds; marker -> body."""
    sqs = ctx.client("sqs")
    seen: dict[str, dict] = {}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            marker = _marker_of(body)
            if marker:
                seen[marker] = body
    return seen


def _await_marker(ctx, queue_url: str, marker: str, timeout_s: float) -> tuple[dict | None, dict[str, dict]]:
    """Drain ``queue_url`` until ``marker`` arrives or ``timeout_s`` passes; (its body or None, all seen)."""
    seen: dict[str, dict] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        seen.update(_drain(ctx, queue_url, 4.0))
        if marker in seen:
            return seen[marker], seen
    return None, seen


def _converge(ctx, source: str, queue_url: str, label: str, attempts: int = 20, streak: int = 3) -> dict[str, dict]:
    """Send probes from ``source`` until ``streak`` in a row reach ``queue_url``: a rule or target
    update is eventually consistent, so the claim is graded only once the update is stably live."""
    seen: dict[str, dict] = {}
    run_of = 0
    for i in range(attempts):
        probe = f"{label}-probe-{i}-{uuid.uuid4().hex}"
        _put(ctx, source, probe)
        body, got = _await_marker(ctx, queue_url, probe, 15.0)
        seen.update(got)
        run_of = run_of + 1 if body is not None else 0
        if run_of >= streak:
            return seen
    raise AssertionError(f"{label} probes did not reach their queue {streak} times in a row within {attempts} attempts")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
