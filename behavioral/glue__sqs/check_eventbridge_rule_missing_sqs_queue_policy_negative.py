"""eventbridge-rule-missing-sqs-queue-policy-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-missing-sqs-queue-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Glue-shaped event matched by one rule lands on the queue whose policy grants events.amazonaws.com
    sqs:SendMessage and never on the sibling queue without that grant. The event uses a non-"aws."
    source, since PutEvents refuses aws.glue from a customer."""
    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["sim2real.glue"],
            "detail-type": ["Glue Crawler State Change"],
        },
    )

    unguarded_url, unguarded_arn = _create_queue(ctx)
    # Deliberately break exactly one thing: no resource policy at all on this queue.

    guarded_url, guarded_arn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, guarded_url, guarded_arn, rule_arn)

    events = ctx.client("events")
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "sim2real-unguarded", "Arn": unguarded_arn},
            {"Id": "sim2real-guarded", "Arn": guarded_arn},
        ],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(
            Rule=rule_name, Ids=["sim2real-unguarded", "sim2real-guarded"]
        )
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

    # Positive control: the guarded sibling queue, same rule, same event, DOES receive it.
    # Resending periodically (rather than a single PutEvents) absorbs SQS resource-policy
    # propagation lag without depending on EventBridge's own much-slower retry backoff.
    started = time.monotonic()
    body = _send_until_received(
        ctx,
        _entries,
        guarded_url,
        lambda b: isinstance(b, dict)
        and b.get("detail", {}).get("crawlerName") == crawler_name,
        timeout_s=150.0,
    )
    assert body["detail"]["state"] == "Succeeded", (
        f"positive control: guarded queue should receive the Succeeded event, got {body!r}"
    )

    # The unguarded queue must never receive the event, even after the same resends.
    # The same events would carry a leak, so the window is 3x the control's arrival time, at
    # least 15 s and never more than 60 s.
    window_s = min(60.0, max(15.0, 3.0 * (time.monotonic() - started)))
    messages = _collect_messages(ctx, unguarded_url, window_s=window_s)
    assert messages == [], (
        "event was delivered to the unguarded queue despite it having no resource "
        f"policy granting events.amazonaws.com sqs:SendMessage; got {len(messages)} message(s)"
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
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-glue-evt-")
    url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
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
            put_resp = events.put_events(Entries=entries_factory())
            if put_resp.get("FailedEntryCount", 0):
                raise AssertionError(f"PutEvents entry failed: {put_resp['Entries']}")
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


def _collect_messages(ctx, queue_url: str, window_s: float) -> list[dict[str, Any]]:
    """Poll a queue for a bounded window and return whatever (if anything) arrived,
    deleting each so the queue is left empty for cleanup."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(10, max(1, int(deadline - time.monotonic()))),
        )
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
