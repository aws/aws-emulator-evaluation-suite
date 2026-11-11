"""cloudfront-distribution-deployed-event-delivered-to-sqs."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cloudfront-distribution-deployed-event-delivered-to-sqs"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A simulated aws.cloudfront 'CloudFront Distribution State Change' event with state
    Deployed matches an EventBridge rule and is delivered to an SQS queue target with the
    detail payload intact."""
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

    marker = ctx.unique_name("dist-")
    entries = [
        {
            "Source": "sim2real.cloudfront",
            "DetailType": "CloudFront Distribution State Change",
            "Detail": json.dumps(
                {
                    "distributionId": marker,
                    "state": "Deployed",
                    "eTag": "E2QWRUHXXXXXXX",
                }
            ),
        }
    ]
    put_resp = events.put_events(Entries=entries)
    assert put_resp.get("FailedEntryCount", 0) == 0, (
        f"put_events failed: {put_resp.get('Entries')}"
    )

    messages = _drain_queue(
        ctx,
        queue["url"],
        timeout_s=90.0,
        resend=lambda: events.put_events(Entries=entries),
        until=lambda ms: any(marker in m["Body"] for m in ms),
    )
    matching = [m for m in messages if marker in m["Body"]]
    assert matching, (
        f"expected a message with distributionId {marker}, "
        f"got {[m['Body'] for m in messages]}"
    )
    body = json.loads(matching[0]["Body"])
    assert body["source"] == "sim2real.cloudfront", (
        f"expected source 'sim2real.cloudfront', got {body['source']!r}"
    )
    assert body["detail-type"] == "CloudFront Distribution State Change", (
        f"expected detail-type 'CloudFront Distribution State Change', "
        f"got {body['detail-type']!r}"
    )
    assert body["detail"]["state"] == "Deployed", (
        f"expected detail.state 'Deployed', got {body['detail']['state']!r}"
    )
    assert body["detail"]["distributionId"] == marker, (
        f"expected detail.distributionId {marker!r}, "
        f"got {body['detail']['distributionId']!r}"
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        QueueName=q_name, tags={"sim2real-check": CHECK}
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
