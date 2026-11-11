"""put-events-unmatched-entry-not-delivered."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-events-unmatched-entry-not-delivered"
GROUP = "telemetry"
SERVICES = ["events"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutEvents entry that does not match the rule's pattern is never delivered to the
    rule's target, while a matching entry sent in the SAME batch (positive control) is -- this
    distinguishes accepted-but-undelivered from actually delivered."""
    events = ctx.client("events")

    rule_name = ctx.unique_name("sim2real-evb-rule-")
    matched_source = ctx.unique_name("sim2real.match.")
    unmatched_source = ctx.unique_name("sim2real.nomatch.")
    detail_type = "sim2real-selective-type"

    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [matched_source], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    queue_url, queue_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)

    # IAM/SQS resource-policy changes can take a little while to propagate; give EventBridge
    # a head start before registering the target so the very first delivery attempt doesn't
    # race a not-yet-visible policy (which some backends will not retry indefinitely).
    _wait_for_policy_visible(ctx, queue_url)

    put_targets_resp = events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}])
    assert put_targets_resp["FailedEntryCount"] == 0, f"put_targets failed: {put_targets_resp}"
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sim2real-target"]))

    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert any(t["Arn"] == queue_arn for t in targets), "target was not registered on the rule"

    matched_marker = ctx.unique_name("matched-marker-")
    unmatched_marker = ctx.unique_name("unmatched-marker-")

    put_events_resp = events.put_events(
        Entries=[
            {
                "Source": matched_source,
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": matched_marker}),
            },
            {
                # Same DetailType, but a Source the rule's pattern does not select.
                "Source": unmatched_source,
                "DetailType": detail_type,
                "Detail": json.dumps({"marker": unmatched_marker}),
            },
        ]
    )
    assert put_events_resp["FailedEntryCount"] == 0, f"put_events failed: {put_events_resp}"

    seen_markers = _drain_and_hold(ctx, queue_url, matched_marker, timeout_s=120.0)
    assert matched_marker in seen_markers, "matching entry (positive control) was never delivered"
    assert unmatched_marker not in seen_markers, (
        "non-matching entry was delivered even though it does not satisfy the rule's EventPattern"
    )


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-evb-queue-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
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


def _wait_for_policy_visible(ctx, queue_url: str, timeout_s: float = 30.0) -> None:
    """Poll GetQueueAttributes until the just-set resource Policy is readable back, as a
    (best-effort) signal that the policy write has propagated before we register the target."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"]
        if attrs.get("Policy"):
            return
        time.sleep(2)


def _drain_and_hold(ctx, queue_url: str, target_marker: str, timeout_s: float) -> set[str]:
    """Drain until the positive control (target_marker) is seen, measuring its own delivery
    latency L, then keep draining for a further >=3L (floor 15s) before declaring anything
    else absent -- a stop-the-instant-the-positive-arrives window would let a target that
    delivers the non-matching entry with extra lag escape detection. Finishes with an
    independent observable (queue depth) rather than trusting an empty receive alone."""
    sqs = ctx.client("sqs")
    seen: set[str] = set()

    def _drain_until(deadline: float, stop_once_seen: str | None) -> None:
        while time.monotonic() < deadline:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                body = json.loads(msg["Body"])
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                marker = body.get("detail", {}).get("marker") if isinstance(body.get("detail"), dict) else None
                if marker:
                    seen.add(marker)
            if stop_once_seen is not None and stop_once_seen in seen:
                return

    start = time.monotonic()
    _drain_until(start + timeout_s, stop_once_seen=target_marker)
    if target_marker not in seen:
        raise AssertionError(f"target marker {target_marker} never arrived within {timeout_s}s")

    latency_s = time.monotonic() - start
    hold_s = max(15.0, latency_s * 3)
    _drain_until(time.monotonic() + hold_s, stop_once_seen=None)

    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue still reports pending messages after the {hold_s:.1f}s hold window: {attrs}"
    )
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
