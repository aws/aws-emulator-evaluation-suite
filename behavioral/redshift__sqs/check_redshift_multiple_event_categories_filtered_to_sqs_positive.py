"""redshift-multiple-event-categories-filtered-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "redshift-multiple-event-categories-filtered-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A rule filtering detail-type "Redshift Integration Monitoring" delivers that event to SQS, while a
    "Redshift Integration Configuration" event on the same source is not delivered (depth "0")."""
    token_monitoring = ctx.unique_name("sim2real-mon-")
    token_configuration = ctx.unique_name("sim2real-cfg-")

    queue = _create_queue(ctx, "catfilter-q")
    rule = _create_rule(
        ctx,
        "catfilter-rule",
        {"source": ["sim2real.redshift"], "detail-type": ["Redshift Integration Monitoring"]},
    )
    _set_queue_policy(ctx, queue, rule["arn"])
    _put_target(ctx, rule["name"], "1", queue["arn"])

    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "Redshift Integration Monitoring",
                "Detail": json.dumps({"correlationId": token_monitoring, "status": "Active"}),
            }
        ]
    )

    t_calib = time.monotonic()
    messages = _poll_messages(ctx, queue["url"], min_count=1, timeout_s=90.0)
    positive_latency_s = time.monotonic() - t_calib
    assert len(messages) >= 1, "matching-category event was never delivered within 90s"
    body = json.loads(messages[0]["Body"])
    assert body["detail-type"] == "Redshift Integration Monitoring", (
        f"expected delivered detail-type 'Redshift Integration Monitoring', got {body['detail-type']!r}"
    )
    assert body["detail"]["correlationId"] == token_monitoring, (
        f"expected correlationId {token_monitoring!r}, got {body['detail'].get('correlationId')!r}"
    )

    # Now send an event on the same source but a sibling category the rule does
    # not select; it must never reach the queue. The absence window is calibrated
    # off the latency the matching category just needed on this same wiring, not a
    # fixed guess, so a correct-but-slower target is never mistaken for a blocked one.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "Redshift Integration Configuration",
                "Detail": json.dumps({"correlationId": token_configuration, "status": "Changed"}),
            }
        ]
    )
    absence_window_s = min(max(3.0 * positive_latency_s, 15.0), 120.0)
    _assert_absent(ctx, queue["url"], timeout_s=absence_window_s)


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-{suffix}-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url, "arn": _queue_arn(sqs, url)}


def _set_queue_policy(ctx, queue: dict, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeRule",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})


def _create_rule(ctx, suffix: str, pattern: dict) -> dict:
    events = ctx.client("events")
    name = ctx.unique_name(f"sim2real-{suffix}-")
    resp = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, queue_arn: str, **extra) -> None:
    events = ctx.client("events")
    target = {"Id": target_id, "Arn": queue_arn, **extra}
    events.put_targets(Rule=rule_name, Targets=[target])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _poll_messages(ctx, queue_url: str, min_count: int = 1, timeout_s: float = 90.0):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _assert_absent(ctx, queue_url: str, timeout_s: float) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    leaked = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            leaked.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if leaked:
            break
    if leaked:
        raise AssertionError(f"expected no message for the unmatched category, got {len(leaked)}")
    # Second, independent observable: the queue's own reported depth, not just an empty receive.
    depth = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"])
    count = depth["Attributes"]["ApproximateNumberOfMessages"]
    assert count == "0", f"expected ApproximateNumberOfMessages == '0' after the absence window, got {count!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
