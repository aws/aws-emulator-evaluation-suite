"""notification-sqs-test-event-format."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-sqs-test-event-format"
GROUP = "notifications"
SERVICES = ["s3"]

_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket, register teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _delete_queue(sqs, queue_url):
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _new_queue(ctx, sqs, bucket):
    """Create a uniquely-named queue, permit S3 to send to it, tag it, register teardown,
    return (queue_url, queue_arn)."""
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, queue_url))
    sqs.tag_queue(QueueUrl=queue_url, Tags={"sim2real": CHECK})
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
                }
            ],
        }
    )
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": policy})
    return queue_url, queue_arn


@tags("axis:happy-path", "cap:c1", "concern:eventing", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The first PutBucketNotificationConfiguration to an SQS queue delivers a flat s3:TestEvent
    (Service, Event, Time, Bucket, RequestId, HostId; no Records) before any real event."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _new_bucket(ctx, s3)
    queue_url, queue_arn = _new_queue(ctx, sqs, bucket)

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={"QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]},
    )

    body = _receive_one(ctx, sqs, queue_url)

    assert set(body) == {"Service", "Event", "Time", "Bucket", "RequestId", "HostId"}, (
        f"expected the flat test-event field set, got keys {sorted(body)!r} in {body!r}"
    )
    assert body["Service"] == "Amazon S3", f"expected Service 'Amazon S3', got {body['Service']!r}"
    assert body["Event"] == "s3:TestEvent", f"expected Event 's3:TestEvent', got {body['Event']!r}"
    assert body["Bucket"] == bucket, f"expected Bucket {bucket!r}, got {body['Bucket']!r}"
    assert _TIME_RE.match(body["Time"]), f"expected an ISO-8601 millisecond UTC Time, got {body['Time']!r}"
    assert isinstance(body["RequestId"], str) and body["RequestId"], (
        f"expected a non-empty RequestId, got {body['RequestId']!r}"
    )
    assert isinstance(body["HostId"], str) and body["HostId"], (
        f"expected a non-empty HostId, got {body['HostId']!r}"
    )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the run's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _receive_one(ctx, sqs, queue_url: str, cap_s: float = 60.0) -> dict:
    """The JSON body of the first message on the queue, deleted once read; none within the
    budget raises TimeoutError."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        wait = int(min(2, max(0, deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait)
        messages = resp.get("Messages", [])
        if messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
            return json.loads(messages[0]["Body"])
        if time.monotonic() >= deadline:
            raise TimeoutError(f"no message arrived on the configured queue within {timeout_s:.0f}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
