"""sqs-queue-policy-explicit-deny-blocks-eventbridge-delivery."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sqs-queue-policy-explicit-deny-blocks-eventbridge-delivery"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "sqs"]

_SOURCE = "custom.denytest"
_DETAIL_TYPE = "Test"


def _allow_policy(queue_arn: str, rule_arn: str) -> dict:
    return {
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


def _allow_and_deny_policy(queue_arn: str, rule_arn: str) -> dict:
    policy = _allow_policy(queue_arn, rule_arn)
    policy["Statement"].append(
        {
            "Sid": "ExplicitDeny",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }
    )
    return policy


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit Deny in the queue policy blocks EventBridge delivery that the Allow statement
    alone permits; delivery works before the Deny is added and resumes after it is removed."""
    queue = _create_queue(ctx)
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    rule_name = ctx.unique_name("rule-deny-")
    rule = events.put_rule(
        Name=rule_name, EventPattern=json.dumps({"source": [_SOURCE]})
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    allow_policy = _allow_policy(queue["arn"], rule["RuleArn"])
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(allow_policy)}
    )

    # Positive control: Allow-only policy delivers, and its latency bounds the
    # calibrated absence window below.
    control_start = time.monotonic()
    marker_control = ctx.unique_name("control-")
    _put_event(ctx, marker_control)
    control = _drain_queue_for(ctx, queue["url"], marker_control, timeout_s=45.0)
    assert control is not None, "positive control failed: Allow-only policy never delivered"
    positive_latency_s = time.monotonic() - control_start

    # Break exactly one thing: add an explicit Deny for the same principal/resource/condition.
    deny_policy = _allow_and_deny_policy(queue["arn"], rule["RuleArn"])
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(deny_policy)}
    )
    marker_denied = ctx.unique_name("denied-")
    _put_event(ctx, marker_denied)
    absence_window_s = max(15.0, 3 * positive_latency_s)
    denied = _drain_queue_for(ctx, queue["url"], marker_denied, timeout_s=absence_window_s)
    assert denied is None, "Explicit Deny must not be overridden by the Allow statement"
    depth = sqs.get_queue_attributes(
        QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", f"queue should hold nothing while delivery is denied, got {depth}"

    # Restore: drop the Deny; the identical call now succeeds.
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(allow_policy)}
    )
    deadline = time.monotonic() + 60.0
    restored = None
    while time.monotonic() < deadline and restored is None:
        marker_restored = ctx.unique_name("restored-")
        _put_event(ctx, marker_restored)
        restored = _drain_queue_for(ctx, queue["url"], marker_restored, timeout_s=8.0)
    assert restored is not None, "delivery never resumed after removing the explicit Deny"


def _put_event(ctx, marker: str) -> None:
    ctx.client("events").put_events(
        Entries=[
            {
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )


def _detail_marker(body):
    if not isinstance(body, dict):
        return None
    detail = body.get("detail")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (json.JSONDecodeError, ValueError):
            return None
    if isinstance(detail, dict):
        return detail.get("marker")
    return None


def _drain_queue_for(ctx, queue_url, marker, timeout_s=60.0, interval_s=2.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            if _detail_marker(body) == marker:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        time.sleep(interval_s)
    return None


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
