"""glue-crawler-event-queue-message-format-positive."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-event-queue-message-format-positive"
GROUP = "data-format"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The JSON an S3 bucket actually deposits on an SQS queue (the exact wire shape
    a Glue crawler EventQueueArn target is documented to consume) has the
    Records[].s3.bucket.name / s3.object.key / eventName schema the crawler parses."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")

    sts.get_caller_identity()["Account"]
    queue_url, queue_arn = _create_queue(ctx)

    policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-s3-to-sqs",
        "Statement": [{
            "Sid": "AllowS3SendMessage",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    bucket = _create_bucket(ctx)
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [{
                "QueueArn": queue_arn,
                "Events": ["s3:ObjectCreated:*"],
            }]
        },
    )

    key = "crawler-format-check/data.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=b"id,val\n1,a\n")

    message = _wait_for_message(ctx, queue_url, timeout_s=90.0)
    envelope = json.loads(message["Body"])

    assert "Records" in envelope and len(envelope["Records"]) >= 1, f"expected a Records[] envelope, got {envelope!r}"
    record = envelope["Records"][0]
    assert record["eventSource"] == "aws:s3", f"expected eventSource aws:s3, got {record['eventSource']!r}"
    assert record["eventName"].startswith("ObjectCreated"), record["eventName"]
    assert record["awsRegion"] == ctx.region, f"expected awsRegion {ctx.region!r}, got {record['awsRegion']!r}"
    s3_block = record["s3"]
    assert s3_block["s3SchemaVersion"] == "1.0", f"expected s3SchemaVersion 1.0, got {s3_block['s3SchemaVersion']!r}"
    assert s3_block["bucket"]["name"] == bucket, f"expected bucket {bucket!r}, got {s3_block['bucket']['name']!r}"
    delivered_key = urllib.parse.unquote_plus(s3_block["object"]["key"])
    assert delivered_key == key, f"expected key {key!r}, got {delivered_key!r}"
    expected_size = len(b"id,val\n1,a\n")
    assert int(s3_block["object"]["size"]) == expected_size, f"expected size {expected_size}, got {s3_block['object']['size']!r}"


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-glue-fmt-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-fmt-")
    # us-east-1 rejects an explicit LocationConstraint for its own region — a
    # target-region literal, not a stand-in for ctx.region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


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


def _wait_for_message(ctx, queue_url: str, timeout_s: float = 90.0) -> dict:
    # S3 sends a synchronous s3:TestEvent message immediately after
    # put_bucket_notification_configuration, ahead of the real ObjectCreated
    # event — skip it (and anything else without a "Records" envelope) and
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
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(body, dict) and "Records" in body:
                return msg
    raise AssertionError(f"no S3 event notification arrived on the queue within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
