"""put-record-batch-oversized-record-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-oversized-record-rejected"
GROUP = "data-plane"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecordBatch with one record over the 1,000 KB limit fails whole with ValidationException;
    an ordinary batch on the same stream succeeds before and after the rejection."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    stream_name = ctx.unique_name("sim2real-behav-fh-")
    _create_delivery_stream_s3(
        ctx, stream_name, role_arn, f"arn:aws:s3:::{bucket}",
        {"IntervalInSeconds": 60, "SizeInMBs": 128},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    fh = ctx.client("firehose")

    # positive control: an ordinary batch is fully accepted
    control = fh.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": f"ok-{i}\n".encode()} for i in range(3)],
    )
    assert control["FailedPutCount"] == 0, (
        f"positive control must be fully accepted, got FailedPutCount={control['FailedPutCount']!r}"
    )
    assert len(control["RequestResponses"]) == 3, (
        f"expected 3 RequestResponses for 3 records, got {len(control['RequestResponses'])}"
    )
    for i, entry in enumerate(control["RequestResponses"]):
        assert "RecordId" in entry, f"accepted control record {i} must carry a RecordId: {entry!r}"

    # negative: one record exceeds the 1,000 KB per-record limit -> whole call rejected
    oversized = b"z" * 1_100_000
    code, message = _error_code(
        lambda: fh.put_record_batch(
            DeliveryStreamName=stream_name,
            Records=[{"Data": b"fine\n"}, {"Data": oversized}],
        )
    )
    assert code == "ValidationException", (
        f"a batch containing a >1,000 KB record must be rejected wholesale with "
        f"ValidationException, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'records.2.member.data' failed to satisfy "
        "constraint: Member must have length less than or equal to 1024000"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    followup = fh.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": b"after-reject\n"}],
    )
    assert followup["FailedPutCount"] == 0, (
        f"the stream must not be wedged by the rejected call, got "
        f"FailedPutCount={followup['FailedPutCount']!r}"
    )
    assert len(followup["RequestResponses"]) == 1, (
        f"expected 1 RequestResponses entry for the followup record, got "
        f"{len(followup['RequestResponses'])}"
    )
    assert "RecordId" in followup["RequestResponses"][0], (
        f"followup record must carry a RecordId: {followup['RequestResponses'][0]!r}"
    )


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message); a success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-").lower()
    # us-east-1 rejects an explicit LocationConstraint matching the endpoint's own region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
                Tags=[{"Key": "sim2real", "Value": "behavioral"}],
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
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
