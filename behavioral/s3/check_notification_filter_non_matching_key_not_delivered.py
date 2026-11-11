"""notification-filter-non-matching-key-not-delivered."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "notification-filter-non-matching-key-not-delivered"
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


def _create_notified_queue(ctx, bucket):
    """Create an SQS queue whose policy lets `bucket` send it S3 events; returns (url, arn)."""
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
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


def _drain_records(sqs, queue_url, *, timeout_s):
    """Receive-and-delete S3 event records for timeout_s; return keys of s3:Object* records.
    Always burns the full window, since one empty long-poll receive does not mean nothing
    arrives."""
    keys = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except (TypeError, ValueError):
                continue
            if body.get("Event") == "s3:TestEvent":
                continue
            for rec in body.get("Records", []):
                keys.append(rec.get("s3", {}).get("object", {}).get("key"))
    return keys


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A prefix+suffix-filtered S3 notification delivers only keys matching both rules.
    Keys breaking either rule are written but not delivered, and the matching key is still
    delivered afterward."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _new_bucket(ctx, s3)
    queue_url, queue_arn = _create_notified_queue(ctx, bucket)

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "only-incoming-csv",
                    "QueueArn": queue_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [
                                {"Name": "prefix", "Value": "incoming/"},
                                {"Name": "suffix", "Value": ".csv"},
                            ]
                        }
                    },
                }
            ]
        },
    )
    # Burn the s3:TestEvent that configuration emits so it cannot be mistaken for a delivery.
    _drain_records(sqs, queue_url, timeout_s=20)

    # --- Control: the one key that satisfies BOTH rules must be delivered.
    match_key = "incoming/report.csv"
    s3.put_object(Bucket=bucket, Key=match_key, Body=b"a,b\n1,2\n")
    delivered = _drain_records(sqs, queue_url, timeout_s=60)
    assert match_key in delivered, (
        f"matching key {match_key!r} was not delivered within 60s; got {delivered!r} "
        "(the positive half of the filter contract is broken, so the negative half below "
        "would be vacuously true)"
    )

    # --- Negative: break exactly one filter component at a time. None may be delivered.
    non_matching = {
        "other/report.csv": "prefix does not match",
        "incoming/report.json": "suffix does not match",
        "other/report.json": "neither prefix nor suffix matches",
        "report.csv": "suffix matches but the key is at the bucket root",
        "incoming/nested/report.csv.bak": "suffix is .bak, not .csv",
    }
    for key in non_matching:
        s3.put_object(Bucket=bucket, Key=key, Body=b"x")

    leaked = _drain_records(sqs, queue_url, timeout_s=60)
    assert leaked == [], (
        "S3 delivered notifications for keys that do not match the prefix/suffix filter: "
        + ", ".join(f"{k!r} ({non_matching.get(k, 'unexpected key')})" for k in leaked)
    )

    # --- Effect present: the suppressed puts still created real objects. Suppression is a
    # routing decision, NOT a write failure — a target that "passes" by rejecting the put
    # must fail here.
    listed = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    expected = set(non_matching) | {match_key}
    assert listed == expected, f"expected objects {sorted(expected)} to exist, listing had {sorted(listed)}"

    # --- Control still works after the negatives: the filter is not left in a broken state.
    second_match = "incoming/second.csv"
    s3.put_object(Bucket=bucket, Key=second_match, Body=b"c,d\n3,4\n")
    delivered2 = _drain_records(sqs, queue_url, timeout_s=60)
    assert second_match in delivered2, (
        f"matching key {second_match!r} was not delivered after the non-matching puts; "
        f"got {delivered2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
