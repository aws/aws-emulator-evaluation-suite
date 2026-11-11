"""notification-to-sqs."""
from __future__ import annotations
import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "notification-to-sqs"
GROUP = 'notifications'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject fires an s3:ObjectCreated event to a configured SQS queue."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    # Get queue ARN
    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    queue_arn = attrs["Attributes"]["QueueArn"]

    # Set queue policy to allow S3 to send messages
    queue_policy = json.dumps(
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
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": queue_policy})

    # Configure bucket notification
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": queue_arn,
                    "Events": ["s3:ObjectCreated:*"],
                }
            ],
        },
    )

    # Drain the S3 test event that's sent on configuration
    for _ in range(5):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        # Check if we got the test event
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            if body.get("Event") == "s3:TestEvent":
                break
        else:
            continue
        break

    # Put an object to trigger the real notification
    s3.put_object(Bucket=bucket, Key="notify-test.txt", Body=b"trigger-event")

    # Poll SQS for the ObjectCreated event
    received = None
    for _ in range(15):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        messages = resp.get("Messages", [])
        for msg in messages:
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            # Skip any lingering test events
            if body.get("Event") == "s3:TestEvent":
                continue
            if "Records" in body:
                received = body
                break
        if received:
            break
    assert received is not None, "No S3 event notification received within 30s"
    records = received["Records"]
    assert len(records) >= 1, f"expected at least one record, got {records!r}"
    record = records[0]
    assert record["eventSource"] == "aws:s3", f"expected eventSource aws:s3, got {record['eventSource']!r}"
    assert "ObjectCreated" in record["eventName"], f"expected an ObjectCreated event, got {record['eventName']!r}"
    assert record["s3"]["bucket"]["name"] == bucket, (
        f"expected bucket {bucket!r}, got {record['s3']['bucket']['name']!r}"
    )
    assert record["s3"]["object"]["key"] == "notify-test.txt", (
        f"expected key 'notify-test.txt', got {record['s3']['object']['key']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
