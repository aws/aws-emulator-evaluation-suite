"""cloudfront-event-detail-payload-format-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cloudfront-event-detail-payload-format-preserved"
GROUP = "data-format"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The distributionId, state, and eTag fields in a CloudFront distribution state-change
    event's detail block are preserved unchanged (values, types, key casing) through
    delivery to the SQS target."""
    events = ctx.client("events")
    rule = _create_rule(
        ctx,
        {
            "source": ["sim2real.cloudfront"],
            "detail-type": ["CloudFront Distribution State Change"],
        },
    )
    queue = _create_queue_for_events(ctx, rule["arn"])
    _put_target(ctx, rule["name"], "sqs-target", queue["arn"])

    marker = ctx.unique_name("dist-")
    detail = {
        "distributionId": marker,
        "state": "Deployed",
        "eTag": "E2QWRUHXAMPLE99",
    }
    entries = [
        {
            "Source": "sim2real.cloudfront",
            "DetailType": "CloudFront Distribution State Change",
            "Detail": json.dumps(detail),
        }
    ]
    events.put_events(Entries=entries)

    messages = _drain_queue(
        ctx,
        queue["url"],
        timeout_s=90.0,
        resend=lambda: events.put_events(Entries=entries),
        until=lambda ms: any(marker in m["Body"] for m in ms),
    )
    matching = [m for m in messages if marker in m["Body"]]
    assert matching, f"event with distributionId {marker} was never delivered"
    delivered_detail = json.loads(matching[0]["Body"])["detail"]
    assert delivered_detail["distributionId"] == detail["distributionId"], (
        f"distributionId mutated in transit: expected {detail['distributionId']!r}, "
        f"got {delivered_detail['distributionId']!r}"
    )
    assert delivered_detail["state"] == detail["state"], (
        f"state mutated in transit: expected {detail['state']!r}, got {delivered_detail['state']!r}"
    )
    assert delivered_detail["eTag"] == detail["eTag"], (
        f"eTag mutated in transit: expected {detail['eTag']!r}, got {delivered_detail['eTag']!r}"
    )
    assert delivered_detail == detail, (
        f"delivered detail block diverges from published detail: "
        f"expected {detail!r}, got {delivered_detail!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_rule(ctx, event_pattern: dict[str, Any]) -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfrule-")
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": rule_name}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return {"name": rule_name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, target_arn: str) -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _create_queue_for_events(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name("sim2real-cfq-")
    url = sqs.create_queue(QueueName=q_name, tags={"sim2real": q_name})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventsPublish",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _drain_queue(
    ctx, queue_url: str, timeout_s: float = 60.0, until=None, resend=None
) -> list[dict[str, Any]]:
    """Receive and delete messages until until(collected) holds, or for timeout_s without one.
    resend() runs every 15 s meanwhile, so delivery does not wait on EventBridge's retry backoff
    while the queue policy propagates."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    last_send = time.monotonic()
    while time.monotonic() < deadline:
        if resend is not None and time.monotonic() - last_send >= 15.0:
            resend()
            last_send = time.monotonic()
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, max(1, int(deadline - time.monotonic()))),
        )
        msgs = resp.get("Messages", [])
        for m in msgs:
            collected.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if until is not None and until(collected):
            break
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
