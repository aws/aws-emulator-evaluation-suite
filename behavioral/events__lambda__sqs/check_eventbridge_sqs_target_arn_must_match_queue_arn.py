"""eventbridge-sqs-target-arn-must-match-queue-arn."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-sqs-target-arn-must-match-queue-arn"

GROUP = "arn-resolution"

SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Queue policy SourceArn condition must scope delivery to the exact rule ARN."""
    queue = _create_queue(ctx)
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    rule_a_name = ctx.unique_name("rule-sqsarn-a-")
    rule_b_name = ctx.unique_name("rule-sqsarn-b-")
    rule_a = events.put_rule(
        Name=rule_a_name,
        EventPattern=json.dumps(
            {"source": ["custom.sqsarntest"], "detail-type": ["A"]}
        ),
    )
    events.put_rule(
        Name=rule_b_name,
        EventPattern=json.dumps(
            {"source": ["custom.sqsarntest"], "detail-type": ["B"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_a_name))
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_b_name))

    # Queue policy only allows rule A's exact ARN as SourceArn.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRuleAOnly",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_a["RuleArn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )

    events.put_targets(Rule=rule_a_name, Targets=[{"Id": "t", "Arn": queue["arn"]}])
    events.put_targets(Rule=rule_b_name, Targets=[{"Id": "t", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_a_name, Ids=["t"])
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_b_name, Ids=["t"])
    )

    # Positive control: rule A's ARN matches the policy condition, so its event is
    # delivered. Time it, so the negative below can be held for a calibrated multiple
    # of this wiring's own observed latency rather than a guessed sleep.
    start = time.monotonic()
    body = _reemit_until_delivered(
        ctx,
        queue["url"],
        {"Source": "custom.sqsarntest", "DetailType": "A", "Detail": "{}"},
    )[0]["body"]
    positive_latency_s = time.monotonic() - start
    assert body["detail-type"] == "A", f"expected rule A's event, got {body!r}"

    # Negative: rule B targets the same queue but its ARN is not granted by the queue
    # policy, so an event that only matches rule B's pattern must never be delivered.
    # Hold absence for >=3x the measured positive-control latency and confirm with a
    # second independent observable (the queue's own reported depth), not a fixed sleep.
    events.put_events(
        Entries=[{"Source": "custom.sqsarntest", "DetailType": "B", "Detail": "{}"}]
    )
    window_s = max(3 * positive_latency_s, 15.0)
    leaked = _drain_for(ctx, queue["url"], window_s)
    assert leaked == [], f"rule B delivered despite SourceArn policy mismatch: {leaked}"
    depth = _queue_depth(ctx, queue["url"])
    assert depth == 0, f"queue reports {depth} message(s) still enqueued after the absence window"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _collect_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive or timeout_s passes; return what arrived."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return messages


def _drain_for(ctx, queue_url, window_s):
    """Poll and delete any messages that arrive within window_s; return what was seen."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            seen.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _queue_depth(ctx, queue_url):
    """Sum of visible + in-flight messages, per the queue's own reported attributes."""
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
        ],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"]
    )


def _reemit_until_delivered(ctx, queue_url, entry, *, attempts=8, poll_s=6.0):
    """Emit an EventBridge event repeatedly until it lands on the SQS queue; return the messages list.
    A freshly-created rule/target can silently drop the first PutEvents before the path is live, and
    EventBridge never retries a dropped event, so re-emitting is more reliable than one longer wait.
    Raises AssertionError if never delivered."""
    events = ctx.client("events")
    for _ in range(attempts):
        events.put_events(Entries=[entry])
        messages = _collect_messages(ctx, queue_url, expected_count=1, timeout_s=poll_s)
        if messages:
            return messages
    raise AssertionError(
        f"event never delivered to {queue_url} after {attempts} attempts of {poll_s}s each"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
