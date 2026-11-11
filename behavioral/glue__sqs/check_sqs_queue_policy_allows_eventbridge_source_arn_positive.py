"""sqs-queue-policy-allows-eventbridge-source-arn-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sqs-queue-policy-allows-eventbridge-source-arn-positive"
GROUP = "permission-boundary"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue policy granting events.amazonaws.com sqs:SendMessage under an ArnEquals aws:SourceArn
    condition on one rule round-trips intact, and a Glue-shaped event through that rule reaches
    the queue.
    """
    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["sim2real.glue"],
            "detail-type": ["Glue Crawler State Change"],
        },
    )
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, queue_url, queue_arn, rule_arn)
    _put_sqs_target(ctx, rule_name, queue_arn)

    sqs = ctx.client("sqs")
    stored_policy = json.loads(
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])[
            "Attributes"
        ]["Policy"]
    )
    condition = stored_policy["Statement"][0]["Condition"]
    expected_condition = {"ArnEquals": {"aws:SourceArn": rule_arn}}
    assert condition == expected_condition, (
        f"expected queue policy Condition {expected_condition!r} to round-trip, got {condition!r}"
    )

    crawler_name = ctx.unique_name("sim2real-glue-crawler-")

    def _entries():
        return [
            {
                "Source": "sim2real.glue",
                "DetailType": "Glue Crawler State Change",
                "Detail": json.dumps({"crawlerName": crawler_name, "state": "Succeeded"}),
            }
        ]

    body = _send_until_received(
        ctx,
        _entries,
        queue_url,
        lambda b: isinstance(b, dict)
        and b.get("detail", {}).get("crawlerName") == crawler_name,
        timeout_s=150.0,
    )
    assert body["detail"]["state"] == "Succeeded", (
        f"expected delivered detail.state 'Succeeded', got {body['detail'].get('state')!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-rule-")
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(event_pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-glue-evt-")
    url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": "glue-crawler-evt"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _set_queue_policy_for_rule(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
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


def _put_sqs_target(ctx, rule_name: str, queue_arn: str) -> None:
    events = ctx.client("events")
    target_id = "sim2real-target"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _send_until_received(
    ctx,
    entries_factory,
    queue_url: str,
    predicate,
    *,
    timeout_s: float = 150.0,
    resend_interval_s: float = 20.0,
):
    """Resends the PutEvents entries periodically while polling the queue, to
    absorb SQS resource-policy / EventBridge target propagation lag rather than
    depending on EventBridge's own (much slower) internal retry backoff."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    last_send = 0.0
    found: Any = None
    while time.monotonic() < deadline and found is None:
        if time.monotonic() - last_send >= resend_interval_s:
            resp = events.put_events(Entries=entries_factory())
            if resp.get("FailedEntryCount", 0):
                raise AssertionError(f"PutEvents entry failed: {resp['Entries']}")
            last_send = time.monotonic()
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found is None and predicate(body):
                found = body
    if found is None:
        raise AssertionError(
            f"matching SQS message not received within {timeout_s}s"
        )
    return found


def _drain_queue_until_match(ctx, queue_url: str, predicate, timeout_s=300.0, interval_s=5.0):
    sqs = ctx.client("sqs")
    found: dict[str, Any] = {"msg": None}

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found["msg"] is None and predicate(body):
                found["msg"] = body
        return found["msg"]

    _poll_until(
        probe,
        lambda v: v is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="matching SQS message",
    )
    return found["msg"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
