"""sns-to-sqs-missing-queue-policy."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sns-to-sqs-missing-queue-policy"

GROUP = "overly-permissive"

SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A confirmed SNS to SQS subscription delivers nothing and leaves the queue empty while the
    queue policy does not allow sns.amazonaws.com; granting that policy restores delivery."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    sub_arn = sub["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn))

    # Same-account SQS endpoints auto-confirm regardless of the queue's access policy -- confirm
    # that first so the negative below is attributable to the missing policy, not to a pending
    # subscription.
    attrs = _poll_until(
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"],
        lambda a: a.get("PendingConfirmation") == "false",
        timeout_s=30.0,
        description="subscription confirmed",
    )
    assert attrs.get("PendingConfirmation") == "false", (
        f"subscription never confirmed: {attrs!r}"
    )

    marker_blocked = ctx.unique_name("blocked-")
    sns.publish(TopicArn=topic["arn"], Message=marker_blocked)
    seen = _collect(ctx, queue["url"], window_s=30.0)
    assert marker_blocked not in seen, (
        f"SQS received {marker_blocked!r} despite the queue having no policy granting "
        f"sns.amazonaws.com sqs:SendMessage -- seen: {seen!r}"
    )
    depth = int(
        sqs.get_queue_attributes(
            QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
    )
    assert depth == 0, f"queue depth was {depth} after the withheld publish; expected 0"

    policy = _allow_service_send(queue["arn"], "sns.amazonaws.com", topic["arn"])
    _set_queue_policy(ctx, queue["url"], policy)
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=queue["url"], AttributeNames=["Policy"])[
            "Attributes"
        ].get("Policy", ""),
        lambda p: "AllowServiceSend" in p,
        timeout_s=30.0,
        description="queue policy reflects the grant",
    )

    marker_allowed = ctx.unique_name("allowed-")
    sns.publish(TopicArn=topic["arn"], Message=marker_allowed)
    delivered = _wait_for(ctx, queue["url"], marker_allowed, timeout_s=30.0)
    assert delivered, (
        "message was still not delivered after granting the queue policy (positive control "
        "failed) -- the withheld leg above cannot be trusted without this"
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


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _body_message(msg: dict) -> Any:
    """Parse an SQS message body's SNS envelope and return the inner Message, falling back to the
    raw string for a non-JSON body."""
    raw = msg.get("Body", "")
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw
    return body.get("Message") if isinstance(body, dict) else body


def _collect(ctx, queue_url: str, *, window_s: float) -> list[Any]:
    """Long-poll the queue for the whole window and return every message body seen, deleting each
    as it is read. Absence over this window is only meaningful once a positive control on the same
    wiring has independently proven delivery works -- used alone this would score a target with no
    delivery path at all as passing."""
    sqs = ctx.client("sqs")
    seen: list[Any] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            seen.append(_body_message(msg))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _wait_for(ctx, queue_url: str, marker: str, *, timeout_s: float) -> bool:
    """Bounded retry: poll until `marker` arrives; return True/False (never raises)."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if _body_message(msg) == marker:
                return True
    return False


def _poll_until(
    probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 1.0, description: str = "condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
