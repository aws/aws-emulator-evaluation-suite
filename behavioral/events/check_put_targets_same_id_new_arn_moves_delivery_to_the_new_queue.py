"""put-targets-same-id-new-arn-moves-delivery-to-the-new-queue."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "put-targets-same-id-new-arn-moves-delivery-to-the-new-queue"
GROUP = "routing"
SERVICES = ["events"]

_DETAIL_TYPE = "sim2real-target-upsert"
_TARGET_ID = "sim2real-target"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTargets reusing a target Id with queue B and an InputTransformer replaces the target: one
    target lists with B's ARN and the transformer, and the next event reaches B transformed, not A.
    """
    events = ctx.client("events")
    rule = ctx.unique_name("sim2real-evb-upsert-")
    source = ctx.unique_name("sim2real.upsert.")
    rule_arn = events.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": [source], "detail-type": [_DETAIL_TYPE]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule))
    a_url, a_arn = _create_queue_for_rule(ctx, rule_arn, "sim2real-evb-upsert-a-")
    b_url, b_arn = _create_queue_for_rule(ctx, rule_arn, "sim2real-evb-upsert-b-")

    resp = events.put_targets(Rule=rule, Targets=[{"Id": _TARGET_ID, "Arn": a_arn}])
    assert resp["FailedEntryCount"] == 0, f"PutTargets (queue A) failed: {resp['FailedEntries']!r}"
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=[_TARGET_ID]))
    _converge(ctx, source, a_url, "queue-a")

    transformer = {
        "InputPathsMap": {"m": "$.detail.marker"},
        "InputTemplate": '{"via": "queue-b", "marker": <m>}',
    }
    resp = events.put_targets(
        Rule=rule, Targets=[{"Id": _TARGET_ID, "Arn": b_arn, "InputTransformer": transformer}]
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets (same Id, queue B) failed: {resp['FailedEntries']!r}"
    targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    assert len(targets) == 1, f"after the same-Id PutTargets the rule lists {len(targets)} targets, expected 1"
    assert targets[0]["Id"] == _TARGET_ID, f"the remaining target has Id {targets[0]['Id']!r}"
    assert targets[0]["Arn"] == b_arn, "the same-Id PutTargets left the target pointing at queue A"
    assert targets[0].get("InputTransformer") == transformer, (
        f"target InputTransformer reads back {targets[0].get('InputTransformer')!r}, expected {transformer!r}"
    )

    _converge(ctx, source, b_url, "queue-b")
    _drain(ctx, a_url, 5.0)

    final = f"after-upsert-{uuid.uuid4().hex}"
    started = time.monotonic()
    _put(ctx, source, final)
    body, _ = _await_marker(ctx, b_url, final, 120.0)
    assert body is not None, "the event put after the upsert never reached queue B"
    assert body == {"via": "queue-b", "marker": final}, f"queue B received {body!r}, not the transformer's rendering"
    stray = _drain(ctx, a_url, max(15.0, 3 * (time.monotonic() - started)))
    assert final not in stray, "the event put after the upsert was also delivered to the replaced queue A"




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
