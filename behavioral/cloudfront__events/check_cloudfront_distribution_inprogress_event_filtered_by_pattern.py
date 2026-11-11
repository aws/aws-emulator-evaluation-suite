"""cloudfront-distribution-inprogress-event-filtered-by-pattern."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cloudfront-distribution-inprogress-event-filtered-by-pattern"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule pattern filtering on detail.state=Deployed does not match an InProgress state
    event, so no message is delivered to the target queue, while a sibling Deployed event
    from the same put_events call IS delivered (positive control)."""
    events = ctx.client("events")
    rule = _create_rule(
        ctx,
        {
            "source": ["sim2real.cloudfront"],
            "detail-type": ["CloudFront Distribution State Change"],
            "detail": {"state": ["Deployed"]},
        },
    )
    queue = _create_queue_for_events(ctx, rule["arn"])
    _put_target(ctx, rule["name"], "sqs-target", queue["arn"])

    deployed_marker = ctx.unique_name("dist-deployed-")
    inprogress_marker = ctx.unique_name("dist-inprogress-")
    put_resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "CloudFront Distribution State Change",
                "Detail": json.dumps(
                    {
                        "distributionId": inprogress_marker,
                        "state": "InProgress",
                        "eTag": "E1AAAAAA",
                    }
                ),
            },
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "CloudFront Distribution State Change",
                "Detail": json.dumps(
                    {
                        "distributionId": deployed_marker,
                        "state": "Deployed",
                        "eTag": "E2BBBBBB",
                    }
                ),
            },
        ]
    )
    assert put_resp.get("FailedEntryCount", 0) == 0, (
        f"put_events failed: {put_resp.get('Entries')}"
    )

    messages = _drain_queue(ctx, queue["url"], timeout_s=90.0)
    bodies = [m["Body"] for m in messages]
    assert any(deployed_marker in b for b in bodies), (
        "positive control failed: the Deployed event was never delivered"
    )
    assert not any(inprogress_marker in b for b in bodies), (
        "InProgress event was delivered despite the detail.state=Deployed pattern filter"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    url = sqs.create_queue(
        QueueName=q_name, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
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
    ctx, queue_url: str, max_messages: int = 10, timeout_s: float = 60.0
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(collected) < max_messages:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        for m in msgs:
            collected.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if not msgs:
            time.sleep(2.0)
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
