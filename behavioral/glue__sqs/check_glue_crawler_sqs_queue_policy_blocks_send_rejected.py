"""glue-crawler-sqs-queue-policy-blocks-send-rejected."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-sqs-queue-policy-blocks-send-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration to a queue whose policy grants glue.amazonaws.com instead
    of S3 raises InvalidArgument with the exact message and stores no queue configuration; with
    S3 granted it persists and delivers the object's event.
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    queue_url, queue_arn = _create_queue(ctx)
    bucket = _create_bucket(ctx)

    wrong_policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-wrong-principal",
        "Statement": [{
            "Sid": "AllowGlueNotS3",
            "Effect": "Allow",
            "Principal": {"Service": "glue.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(wrong_policy)})

    notif_config = {
        "QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]
    }

    code, message = _error(lambda: s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration=notif_config,
    ))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    expected_message = "Unable to validate the following destination configurations"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect absent: the bucket has no notification configuration wired to the queue
    current = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert not current.get("QueueConfigurations"), f"unexpected queue wiring persisted: {current}"

    # positive control: same bucket/queue pair, correct principal, succeeds
    correct_policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-correct-principal",
        "Statement": [{
            "Sid": "AllowS3SendMessage",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(correct_policy)})
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration=notif_config)
    confirmed = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert confirmed.get("QueueConfigurations"), "expected the wiring to persist with the correct principal"

    # terminal read at the consumer: the wiring must actually forward a real event,
    # not just be accepted and echoed back by the producer's own config read
    key = "queue-policy-positive-control/data.csv"
    body = b"id,val\n1,a\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    message = _wait_for_s3_event(ctx, queue_url, timeout_s=90.0)
    envelope = json.loads(message["Body"])
    record = envelope["Records"][0]
    assert record["s3"]["bucket"]["name"] == bucket, record["s3"]["bucket"]
    delivered_key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
    assert delivered_key == key, f"expected key {key!r}, got {delivered_key!r}"


def _error(fn) -> tuple[str, str]:
    """Return fn()'s ClientError code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-polq-"), tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-polb-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _wait_for_s3_event(ctx, queue_url: str, timeout_s: float = 90.0) -> dict:
    # S3 sends a synchronous s3:TestEvent message immediately after
    # put_bucket_notification_configuration, ahead of the real ObjectCreated
    # event -- skip it (and anything else without a "Records" envelope) and
    # keep polling for the actual S3 event notification.
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        messages = resp.get("Messages", [])
        if messages:
            msg = messages[0]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                parsed = json.loads(msg["Body"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(parsed, dict) and parsed.get("Records"):
                return msg
    raise AssertionError(f"no S3 event notification arrived on the queue within {timeout_s}s")


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
