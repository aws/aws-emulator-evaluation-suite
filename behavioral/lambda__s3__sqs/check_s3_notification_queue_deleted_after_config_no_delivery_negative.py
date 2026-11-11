"""s3-notification-queue-deleted-after-config-no-delivery-negative."""
from __future__ import annotations

import json
import time
from typing import Any

import botocore

from behavioral_harness import tags

CHECK = "s3-notification-queue-deleted-after-config-no-delivery-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An upload delivers a notification while the target queue exists; after the queue is deleted,
    S3 still stores the next object and the queue answers NonExistentQueue (exact message) to
    reads and sends."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket_name = _create_bucket(ctx)
    queue_url, queue_arn = _create_queue_no_cleanup(ctx)
    _set_queue_policy_for_s3(ctx, queue_url, queue_arn, bucket_name)

    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "QueueConfigurations": [
                {"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )

    # Positive control while the queue still exists.
    control_key = "before-deletion.txt"
    s3.put_object(Bucket=bucket_name, Key=control_key, Body=b"still-wired-up")
    control_records = _poll_for_records(ctx, queue_url, timeout_s=90.0)
    assert any(r["s3"]["object"]["key"] == control_key for r in control_records), (
        f"positive control was never delivered before deletion: {control_records}"
    )

    sqs.delete_queue(QueueUrl=queue_url)
    # SQS documents that queue deletion can take up to ~60s to fully propagate:
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-delete-queue.html
    # Poll for the queue to actually be gone before exercising the broken-destination path.
    def _queue_code():
        try:
            sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        except botocore.exceptions.ClientError as err:
            return err.response["Error"]["Code"]
        return "<queue still exists>"

    _poll_until(
        _queue_code,
        lambda code: code == "AWS.SimpleQueueService.NonExistentQueue",
        timeout_s=90.0,
        interval_s=5.0,
        description=f"queue {queue_url} fully deleted",
    )

    # The destination is now gone; S3 must still accept the write, and the object
    # must actually persist with the bytes we sent (an independent read at the S3
    # side, not just the mutating call's own response).
    broken_key = "after-deletion.txt"
    broken_body = b"orphaned-notification"
    s3.put_object(Bucket=bucket_name, Key=broken_key, Body=broken_body)
    persisted = s3.get_object(Bucket=bucket_name, Key=broken_key)["Body"].read()
    assert persisted == broken_body, (
        f"object write must persist even though the notification target is gone, got {persisted!r}"
    )

    # And there is categorically no way the message reached the (deleted) queue:
    # the queue itself is still gone, and the exact send S3 would perform also fails.
    final_code, final_message = _expect_error(
        lambda: sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
    )
    assert final_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"deleted queue must still read as gone, got {final_code!r}"
    )
    assert final_message == "The specified queue does not exist.", (
        f"expected NonExistentQueue message 'The specified queue does not exist.', got {final_message!r}"
    )
    send_code, send_message = _expect_error(lambda: sqs.send_message(QueueUrl=queue_url, MessageBody="probe"))
    assert send_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"a direct SendMessage to the deleted queue must fail the same way S3's own delivery would, got {send_code!r}"
    )
    assert send_message == "The specified queue does not exist.", (
        f"expected NonExistentQueue message 'The specified queue does not exist.', got {send_message!r}"
    )


def _expect_error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-s3neg-bkt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", [])
            ]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    if versioned:
        s3.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
    return bucket_name


def _create_queue_no_cleanup(ctx) -> tuple[str, str]:
    """This check deletes the queue itself mid-run, so no delete_queue cleanup is
    registered for it (it would just be a redundant not-found call at teardown)."""
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-s3neg-q-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    sqs.tag_queue(QueueUrl=queue_url, Tags={"sim2real": CHECK})
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _set_queue_policy_for_s3(ctx, queue_url: str, queue_arn: str, bucket_name: str):
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Notify",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SQS:SendMessage",
                "Resource": queue_arn,
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket_name}"}
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _poll_for_records(ctx, queue_url: str, timeout_s: float = 90.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for rec in body.get("Records", []):
                collected.append(rec)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return collected

    _wait_for_effect(
        probe,
        lambda recs: len(recs) > 0,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"S3 event delivered to queue {queue_url}",
    )
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
