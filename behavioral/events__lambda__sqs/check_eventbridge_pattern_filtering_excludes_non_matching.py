"""eventbridge-pattern-filtering-excludes-non-matching."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-pattern-filtering-excludes-non-matching"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule's event pattern excludes non-matching events from being delivered."""
    queue = _create_queue(ctx)
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    rule_name = ctx.unique_name("rule-filter-")
    rule = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["custom.filtertest"], "detail-type": ["Wanted"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule["RuleArn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    # Positive control first: prove the path is live, and measure its own latency so the
    # negative below can be held open for a multiple of it rather than a guessed sleep.
    t0 = time.monotonic()
    matched = _reemit_until_delivered(
        ctx,
        queue["url"],
        {
            "Source": "custom.filtertest",
            "DetailType": "Wanted",
            "Detail": json.dumps({"n": 1}),
        },
    )
    positive_latency_s = time.monotonic() - t0
    body = matched[0]["body"]
    assert body["detail-type"] == "Wanted", (
        f"positive control: expected detail-type 'Wanted', got {body.get('detail-type')!r}"
    )
    assert body["detail"]["n"] == 1, (
        f"positive control: expected detail.n == 1, got {body.get('detail')!r}"
    )

    # Negative: a non-matching event must never be delivered. Hold the queue open for
    # >= 3x the positive control's own measured latency and drain everything that
    # arrives in that window — never just the first message received, since a standard
    # SQS queue does not guarantee delivery order between the two put_events calls.
    events.put_events(
        Entries=[
            {
                "Source": "custom.filtertest",
                "DetailType": "Unwanted",
                "Detail": json.dumps({"n": 2}),
            }
        ]
    )
    window_s = max(positive_latency_s * 3, 15.0)
    drained = _drain_for(ctx, queue["url"], window_s)
    unwanted = [m for m in drained if m["body"].get("detail-type") == "Unwanted"]
    assert not unwanted, (
        f"non-matching event was delivered despite the filter pattern: {unwanted}"
    )

    attrs = _wait_counters_zero(
        ctx,
        sqs,
        queue["url"],
        [
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
        ],
    )
    assert (
        attrs["ApproximateNumberOfMessages"] == "0"
        and attrs["ApproximateNumberOfMessagesNotVisible"] == "0"
    ), f"queue not empty after the drain window: {attrs}"


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes). A stop forced
    by the runner's budget, short of cap_s, is no verdict.
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


def _drain_for(ctx, queue_url, duration_s):
    """Poll the queue for the full duration, deleting and collecting every message that
    arrives — never just the first — since order across two separate put_events calls
    on a standard SQS queue is not guaranteed."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + duration_s
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
            messages.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return messages


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
