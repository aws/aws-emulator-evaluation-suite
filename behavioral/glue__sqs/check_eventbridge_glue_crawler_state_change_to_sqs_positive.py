"""eventbridge-glue-crawler-state-change-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-glue-crawler-state-change-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Glue Crawler State Change events (Succeeded and Failed) match one EventBridge rule that ORs
    two detail.state values and are delivered to its SQS target with source and detail-type intact.
    """
    queue_url, queue_arn = _create_queue(ctx)
    succeeded_crawler = ctx.unique_name("sim2real-glue-crawler-ok-")
    failed_crawler = ctx.unique_name("sim2real-glue-crawler-bad-")
    source = "sim2real.test.glue"
    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": [source],
            "detail-type": ["Glue Crawler State Change"],
            "detail": {"state": ["Succeeded", "Failed"]},
        },
    )
    _wire_rule_to_queue(ctx, rule_name, rule_arn, queue_url, queue_arn)

    events = ctx.client("events")
    entries = [
        {
            "Source": source,
            "DetailType": "Glue Crawler State Change",
            "Detail": json.dumps({"crawlerName": succeeded_crawler, "state": "Succeeded"}),
        },
        {
            "Source": source,
            "DetailType": "Glue Crawler State Change",
            "Detail": json.dumps({"crawlerName": failed_crawler, "state": "Failed"}),
        },
    ]

    messages = _deliver_and_wait(ctx, events, entries, queue_url, expected_min=2, timeout_s=90.0)
    assert len(messages) >= 2, f"expected 2 crawler state events, got {len(messages)}"
    bodies = [json.loads(m["Body"]) for m in messages]
    by_crawler = {b["detail"]["crawlerName"]: b["detail"]["state"] for b in bodies}
    assert by_crawler.get(succeeded_crawler) == "Succeeded", (
        f"expected {succeeded_crawler} delivered with state Succeeded, got {by_crawler.get(succeeded_crawler)!r}"
    )
    assert by_crawler.get(failed_crawler) == "Failed", (
        f"expected {failed_crawler} delivered with state Failed, got {by_crawler.get(failed_crawler)!r}"
    )
    for b in bodies:
        assert b["detail-type"] == "Glue Crawler State Change", (
            f"expected detail-type 'Glue Crawler State Change', got {b['detail-type']!r}"
        )
        assert b["source"] == source, f"expected source {source!r}, got {b['source']!r}"


# ===== helpers =====
def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-sqs-"),
        tags={"sim2real": "glue-crawler-evt"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-glue-rule-")
    rule_arn = events.put_rule(
        Name=name, EventPattern=json.dumps(event_pattern), State="ENABLED"
    )["RuleArn"]

    def _cleanup() -> None:
        try:
            events.remove_targets(Rule=name, Ids=["1"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=name)

    ctx.on_cleanup(_cleanup)
    return name, rule_arn


def _wire_rule_to_queue(ctx, rule_name: str, rule_arn: str, queue_url: str, queue_arn: str) -> None:
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])


def _receive_messages(
    ctx, queue_url: str, expected_min: int = 1, timeout_s: float = 45.0
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_min and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _deliver_and_wait(
    ctx,
    events_client,
    entries: list[dict[str, Any]],
    queue_url: str,
    expected_min: int = 1,
    timeout_s: float = 90.0,
    resend_interval_s: float = 10.0,
) -> list[dict[str, Any]]:
    """Resend the PutEvents entries periodically while polling SQS (absorbs EventBridge
    rule/target and SQS queue-policy propagation delay instead of a fixed sleep)."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    next_send = 0.0
    while time.monotonic() < deadline and len(out) < expected_min:
        now = time.monotonic()
        if now >= next_send:
            events_client.put_events(Entries=entries)
            next_send = now + resend_interval_s
        wait_s = int(max(1.0, min(5.0, next_send - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
