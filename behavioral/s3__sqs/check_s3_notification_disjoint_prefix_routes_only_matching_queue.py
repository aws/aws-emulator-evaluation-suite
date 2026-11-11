"""s3-notification-disjoint-prefix-routes-only-matching-queue."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "s3-notification-disjoint-prefix-routes-only-matching-queue"

GROUP = "event-propagation"

SERVICES = ["s3", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Two prefix-scoped notification configs on one bucket route each object to its own queue
    only: the alpha/ arrival is the barrier for the beta queue staying empty, and a later beta/
    arrival proves the beta leg was live.
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    q_alpha = _create_queue(ctx)
    q_beta = _create_queue(ctx)

    for q in (q_alpha, q_beta):
        _set_queue_policy(
            ctx,
            q["url"],
            _allow_service_send(q["arn"], "s3.amazonaws.com", bucket["arn"]),
        )

    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "alpha",
                    "QueueArn": q_alpha["arn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "alpha/"}]}
                    },
                },
                {
                    "Id": "beta",
                    "QueueArn": q_beta["arn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "beta/"}]}
                    },
                },
            ]
        },
    )

    def _object_keys(msgs):
        """Object keys carried by real notification messages; s3:TestEvent has no Records."""
        keys = []
        for m in msgs:
            b = _body(m)
            if not isinstance(b, dict):
                continue
            for r in b.get("Records", []):
                keys.append(r.get("s3", {}).get("object", {}).get("key"))
        return keys

    # Control 1: the alpha/ object reaches the alpha queue -> the notification config is effective.
    started = time.monotonic()
    s3.put_object(Bucket=bucket["name"], Key="alpha/one.txt", Body=b"a")
    ctl, alpha_others = _wait_for(
        ctx,
        q_alpha["url"],
        lambda b: (
            isinstance(b, dict)
            and any(
                r.get("s3", {}).get("object", {}).get("key") == "alpha/one.txt"
                for r in b.get("Records", [])
            )
        ),
        timeout_s=90.0,
    )
    assert len(ctl) >= 1, "control: alpha/one.txt must notify the alpha-prefixed queue"
    alpha_latency_s = time.monotonic() - started
    # The only non-matching traffic legitimately on this queue is the s3:TestEvent, which carries no
    # Records at all -- any other object key here is over-delivery too.
    assert _object_keys(alpha_others) == [], (
        f"the alpha/-scoped destination received unexpected object notification(s) for "
        f"{_object_keys(alpha_others)}"
    )

    # Negative: the beta queue must not have received the alpha/ event. A leak would be a copy of
    # the same notification, so the window is 3x the control's arrival latency, 15 s to 45 s.
    leak_window_s = min(45.0, max(15.0, 3.0 * alpha_latency_s))
    leaked = _object_keys(_collect(ctx, q_beta["url"], window_s=leak_window_s))
    assert leaked == [], (
        f"the beta/-scoped destination received object notification(s) for {leaked} -- S3 is "
        "fanning every event out to every configured destination instead of applying the per-"
        "destination prefix filter"
    )

    # Control 2: the beta leg really was live while it stayed empty above.
    s3.put_object(Bucket=bucket["name"], Key="beta/two.txt", Body=b"b")
    ctl2, _ = _wait_for(
        ctx,
        q_beta["url"],
        lambda b: (
            isinstance(b, dict)
            and any(
                r.get("s3", {}).get("object", {}).get("key") == "beta/two.txt"
                for r in b.get("Records", [])
            )
        ),
        timeout_s=90.0,
    )
    assert len(ctl2) >= 1, (
        "control: beta/two.txt must notify the beta-prefixed queue -- without this the empty beta "
        "queue above could simply mean the beta destination was never wired"
    )


# ===== helpers =====
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
    and return EVERY message seen.

    This is the NEGATIVE observable. An empty return is only meaningful next to a positive control
    observed elsewhere in the check, which shows a delivery would have arrived in that time; used
    alone it would pass against a target that delivers nothing at all."""
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
    the caller can assert on leakage."""
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


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every object version and delete marker (delete_bucket refuses a non-empty bucket with
    BucketNotEmpty), then delete the bucket."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": targets})
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
