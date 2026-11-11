"""put-record-batch-partial-failure-reported."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-partial-failure-reported"
GROUP = "data-plane"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutRecordBatch accepts exactly 500 records and rejects a 501-record call wholesale with
    ValidationException; a follow-up batch then succeeds and reaches S3, with none of the 501.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/limits.html
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    stream_name = ctx.unique_name("sim2real-behav-fh-")
    _create_delivery_stream_s3(
        ctx, stream_name, role_arn, f"arn:aws:s3:::{bucket}",
        {"IntervalInSeconds": 60, "SizeInMBs": 1},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    fh = ctx.client("firehose")

    at_limit = fh.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": f"rec-{i}\n".encode()} for i in range(500)],
    )
    assert at_limit["FailedPutCount"] == 0, f"expected no per-record failures at the boundary, got {at_limit}"
    assert len(at_limit["RequestResponses"]) == 500, (
        f"expected one response entry per input record, got {len(at_limit['RequestResponses'])}"
    )
    for entry in at_limit["RequestResponses"]:
        assert "ErrorCode" not in entry, f"unexpected per-record ErrorCode at the boundary: {entry}"
        assert "RecordId" in entry, f"accepted record is missing its RecordId: {entry}"

    rejected_marker = ctx.unique_name("over-limit-")
    code, message = _error_code(
        lambda: fh.put_record_batch(
            DeliveryStreamName=stream_name,
            Records=[{"Data": f"{rejected_marker}-{i}\n".encode()} for i in range(501)],
        )
    )
    assert code == "ValidationException", (
        f"expected the 501-record call to be rejected wholesale, got error code {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'records' failed to satisfy constraint: "
        "Member must have length less than or equal to 500"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    followup_marker = ctx.unique_name("after-reject-")
    followup = fh.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": f"{followup_marker}\n".encode()}],
    )
    assert followup["FailedPutCount"] == 0, f"expected the follow-up batch to succeed cleanly, got {followup}"
    assert len(followup["RequestResponses"]) == 1, (
        f"expected exactly one response entry for the follow-up batch, got {len(followup['RequestResponses'])}"
    )
    assert "RecordId" in followup["RequestResponses"][0], (
        f"follow-up record is missing its RecordId: {followup['RequestResponses'][0]}"
    )

    delivered = _wait_for_marker_delivered(ctx, bucket, followup_marker)
    assert rejected_marker.encode() not in delivered, (
        f"the wholesale-rejected 501-record batch was delivered anyway: found "
        f"{rejected_marker!r} among the bytes landed in s3://{bucket}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_for_marker_delivered(ctx, bucket: str, present_marker: str, timeout: float = 180.0) -> bytes:
    """Poll the bucket until `present_marker` appears in the delivered bytes; return all bytes
    delivered so far so the caller can also assert on what is absent."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout
    while True:
        blob = b""
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                blob += s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        if present_marker.encode() in blob:
            return blob
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"marker {present_marker!r} was not delivered to s3://{bucket} within {timeout}s"
            )
        time.sleep(5.0)



def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:check", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_delivery_stream_s3(ctx, name: str, role_arn: str, bucket_arn: str, buffering_hints: dict) -> None:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": bucket_arn,
                    "BufferingHints": buffering_hints,
                },
                Tags=[{"Key": "sim2real:check", "Value": CHECK}],
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            # newly created IAM roles/policies can take a little while to propagate
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _delete_stream(ctx, name: str) -> None:
    fh = ctx.client("firehose")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, name: str, timeout: float = 180.0) -> dict:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream entered CREATING_FAILED: {desc.get('FailureDescription')}")
        time.sleep(3.0)
    raise AssertionError("delivery stream did not become ACTIVE in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
