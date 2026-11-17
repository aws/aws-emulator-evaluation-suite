"""put-record-batch-at-maximum-entry-count-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-at-maximum-entry-count-succeeds"
GROUP = "boundary-validation"
SERVICES = ["firehose"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _access_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }


def _quiet_not_found(fn, *codes: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _wait_active(firehose, name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"{name} did not reach ACTIVE within {timeout_s}s")


def _poll_delivered_lines(s3, bucket: str, want: int, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    lines: list[str] = []
    while time.monotonic() < deadline:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        lines = []
        for obj in objects:
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            lines.extend(ln for ln in body.decode("utf-8").split("\n") if ln)
        if len(lines) >= want:
            return lines
        time.sleep(interval_s)
    return lines


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A single PutRecordBatch call at the documented maximum of 500 records succeeds and
    every one of the 500 records lands in the S3 destination.
    """
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-fh-maxbatch-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-behav-fh-maxbatch-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    policy_name = f"{role_name}-access"
    ctx.on_cleanup(lambda: _quiet_not_found(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
        )
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_access_policy(bucket))
    )

    name = ctx.unique_name("sim2real-behav-fh-maxbatch-")
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
            "ResourceNotFoundException",
        )
    )
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
                },
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    _wait_active(firehose, name)

    total = 500
    expected_markers = {f"max-entry-{i:03d}" for i in range(total)}
    records = [{"Data": (marker + "\n").encode()} for marker in sorted(expected_markers)]
    response = firehose.put_record_batch(DeliveryStreamName=name, Records=records)

    assert response["FailedPutCount"] == 0, (
        f"expected FailedPutCount 0 for a 500-record batch, got {response['FailedPutCount']}"
    )
    assert len(response["RequestResponses"]) == total, (
        f"expected {total} response entries, got {len(response['RequestResponses'])}"
    )
    record_ids = {r["RecordId"] for r in response["RequestResponses"]}
    assert len(record_ids) == total, f"expected {total} unique RecordIds, got {len(record_ids)}"

    lines = _poll_delivered_lines(s3, bucket, want=total, timeout_s=180.0)
    delivered_markers = set(lines)
    assert delivered_markers == expected_markers, (
        f"expected all {total} markers delivered to S3, got {len(delivered_markers)} "
        f"distinct marker(s); missing {sorted(expected_markers - delivered_markers)[:5]}"
    )


def _purge_bucket(s3, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
