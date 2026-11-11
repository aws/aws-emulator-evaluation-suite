"""sns-filter-policy-message-body-scope-suppresses-non-matching."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sns-filter-policy-message-body-scope-suppresses-non-matching"

GROUP = "event-propagation"

SERVICES = ["sns", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A FilterPolicyScope=MessageBody policy is matched against the JSON body: the matching control
    message reaches the queue and the non-matching one, published first, never does."""
    sns = ctx.client("sns")
    topic = _create_topic(ctx)
    q = _create_queue(ctx)
    _set_queue_policy(
        ctx, q["url"], _allow_service_send(q["arn"], "sns.amazonaws.com", topic["arn"])
    )

    sub = sns.subscribe(
        TopicArn=topic["arn"],
        Protocol="sqs",
        Endpoint=q["arn"],
        Attributes={
            "FilterPolicy": json.dumps({"kind": ["wanted"]}),
            "FilterPolicyScope": "MessageBody",
            "RawMessageDelivery": "true",
        },
        ReturnSubscriptionArn=True,
    )
    sub_arn = sub["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn))

    scope = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get(
        "FilterPolicyScope"
    )
    assert scope == "MessageBody", (
        f"FilterPolicyScope did not persist as MessageBody (got {scope!r}); the rest of this check "
        "would be testing the attribute-scope path instead"
    )

    # Non-matching first, so ordered delivery would put it ahead of the control.
    sns.publish(
        TopicArn=topic["arn"],
        Message=json.dumps({"kind": "unwanted", "marker": "suppressed"}),
    )
    sns.publish(
        TopicArn=topic["arn"],
        Message=json.dumps({"kind": "wanted", "marker": "control"}),
    )

    ctl, others = _wait_for(
        ctx,
        q["url"],
        lambda b: isinstance(b, dict) and b.get("marker") == "control",
        timeout_s=90.0,
    )
    assert len(ctl) >= 1, (
        "control: a body matching {'kind': ['wanted']} must be delivered under MessageBody scope"
    )

    others = others + _collect(ctx, q["url"], window_s=30.0)
    bad = [
        _body(m)
        for m in others
        if isinstance(_body(m), dict) and _body(m).get("marker") == "suppressed"
    ]
    assert bad == [], (
        f"the MessageBody-scoped filter policy delivered {len(bad)} non-matching message(s): {bad}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10, keep=False):
    """Drain a queue over a bounded window with long-polling ReceiveMessage(MaxNumberOfMessages=10)
    and return EVERY message seen. Never raises and never swallows an assertion.

    This is the NEGATIVE observable. An empty return is only meaningful once a positive control
    has already been observed elsewhere in the check -- that is what proves enough wall-clock and
    enough propagation elapsed for a delivery to have happened if the emulator were going to make
    one. Used alone it would pass against an emulator that delivers nothing at all."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            if not keep:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.
    Returns (matched, others) -- every non-matching message seen along the way is returned too so
    the caller can assert on leakage rather than silently discarding it."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _allow_service_send(queue_arn: str, service: str, source_arn: str) -> dict:
    """A queue policy granting one AWS service SendMessage on this queue, scoped by SourceArn."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowServiceSend",
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
