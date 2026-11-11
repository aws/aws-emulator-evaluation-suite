"""s3-notification-sqs-missing-policy-negative."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError
from botocore.exceptions import ClientError as BotoClientError

from behavioral_harness import tags

CHECK = "s3-notification-sqs-missing-policy-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

_UNVALIDATED_DESTINATION = "Unable to validate the following destination configurations"


@tags("axis:rejection", "cap:c1", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An SQS notification destination with no policy for S3 fails with InvalidArgument "Unable to
    validate the following destination configurations" and is not stored, while a twin queue with
    the policy receives events; once granted, the same configuration is accepted."""
    bucket = _create_bucket(ctx)
    queue_ok = _create_queue(ctx)
    queue_bad = _create_queue(ctx)  # deliberately left with no policy

    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    _grant_s3_send(sqs, queue_ok, bucket)

    # ---- positive control: a properly-permissioned queue receives the notification ----
    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {"QueueArn": queue_ok["arn"], "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    s3.put_object(Bucket=bucket["name"], Key="control/ok.json", Body=b'{"leg":"control"}')
    _drain_s3_test_events(sqs, queue_ok["url"])
    control_messages = _wait_for_messages(
        ctx, queue_ok["url"], expected_count=1, timeout_s=60
    )
    assert control_messages, (
        "Positive control failed: no notification reached the correctly-permissioned queue, "
        "so a rejection of queue_bad below cannot be attributed to its missing policy"
    )

    # ---- break exactly one thing: point the SAME bucket at a queue with NO policy ----
    err_code = None
    err_msg = ""
    try:
        s3.put_bucket_notification_configuration(
            Bucket=bucket["name"],
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"QueueArn": queue_bad["arn"], "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        )
    except BotoClientError as e:
        err_code = e.response["Error"]["Code"]
        err_msg = e.response["Error"].get("Message", "")

    assert err_code == "InvalidArgument", (
        f"Expected InvalidArgument when the destination queue grants S3 no send permission, "
        f"got {err_code!r}: {err_msg}"
    )
    assert err_msg == _UNVALIDATED_DESTINATION, (
        f"InvalidArgument message {err_msg!r} != {_UNVALIDATED_DESTINATION!r}"
    )

    # ---- effect is absent: the rejected reconfigure did not attach the bad queue ----
    current = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    current_arns = {c["QueueArn"] for c in current.get("QueueConfigurations", [])}
    assert queue_bad["arn"] not in current_arns, (
        f"The rejected PutBucketNotificationConfiguration call still attached queue_bad: "
        f"{current_arns}"
    )

    s3.put_object(Bucket=bucket["name"], Key="blocked/data.json", Body=b"should-not-arrive")
    resp = sqs.receive_message(
        QueueUrl=queue_bad["url"], MaxNumberOfMessages=5, WaitTimeSeconds=10
    )
    assert not resp.get("Messages"), (
        "queue_bad received a message despite never being accepted as a notification target"
    )

    # ---- restore: grant the SAME queue the missing permission ----
    _grant_s3_send(sqs, queue_bad, bucket)

    # ---- the identical call now succeeds, and the independent read confirms it stuck ----
    # Once a (bucket, queue) pair has been rejected, S3 can take over 3 minutes to deliver
    # events to it even after the policy is granted, although the configuration call succeeds at
    # once. So this leg asserts the call's success and its persistence via an independent read,
    # not a delivery through the previously rejected pair.
    _retry_put_notification_config(
        s3,
        bucket["name"],
        {
            "QueueConfigurations": [
                {"QueueArn": queue_bad["arn"], "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    restored = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    restored_arns = {c["QueueArn"] for c in restored.get("QueueConfigurations", [])}
    assert queue_bad["arn"] in restored_arns, (
        f"After granting queue_bad the missing policy, the identical "
        f"PutBucketNotificationConfiguration call did not persist it: {restored_arns}"
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


def _grant_s3_send(sqs_client, queue: dict[str, str], bucket: dict[str, str]) -> None:
    """Attach a resource policy letting s3.amazonaws.com send to `queue`, scoped to `bucket`."""
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue["arn"],
                    "Condition": {"ArnLike": {"aws:SourceArn": bucket["arn"]}},
                }
            ],
        }
    )
    sqs_client.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": policy})


def _retry_put_notification_config(
    s3_client, bucket_name: str, config: dict, timeout_s: float = 20.0, interval_s: float = 2.0
) -> None:
    """Retry PutBucketNotificationConfiguration through the SQS policy-propagation window."""
    deadline = time.monotonic() + timeout_s
    last_err: BotoClientError | None = None
    while time.monotonic() < deadline:
        try:
            s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name, NotificationConfiguration=config
            )
            return
        except BotoClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(
        f"PutBucketNotificationConfiguration kept failing after the policy was granted: {last_err}"
    )


def _msg_body_json(msg: dict) -> dict:
    """Return message body as a parsed dict, whether it arrives as str or dict."""
    raw = msg.get("Body") or msg.get("body", "{}")
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


def _drain_s3_test_events(sqs_client, queue_url: str, timeout_s: int = 15) -> None:
    """Drain S3 TestEvent messages that AWS sends when configuring bucket notifications.

    When a bucket notification is configured, S3 sends a 's3:TestEvent' to each destination.
    This helper drains those probe messages so checks only see real object events.
    """

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            raw = _msg_body_json(msg)
            # If it is a test event, delete it; otherwise leave it (shouldn't happen pre-PutObject)
            if raw.get("Event") == "s3:TestEvent" or raw.get("Service") == "Amazon S3":
                sqs_client.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
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
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Delete every object version and delete marker (versioning may be on), then the bucket:
    DeleteBucket on a non-empty bucket fails with BucketNotEmpty."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


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
