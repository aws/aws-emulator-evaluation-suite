"""firehose-delivery-role-used-for-s3-putobject-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-delivery-role-used-for-s3-putobject-positive"
GROUP = "arn-resolution"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A delivery role scoped to the destination bucket writes a PutRecordBatch (FailedPutCount 0) to S3 under the
    configured prefix, with every delivered line byte-exact and present exactly once."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx, s3, "sim2real-fhbatch-dst")

    # Least-privilege: resource ARNs scoped to this one bucket only, nothing broader.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:AbortMultipartUpload",
                "s3:ListBucketMultipartUploads",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    role_name = ctx.unique_name("sim2real-fhbatch-role-")
    role_arn = _create_role(ctx, iam, role_name, "firehose.amazonaws.com", policy_doc)

    stream_name = ctx.unique_name("sim2real-fhbatch-stream-")
    prefix = "firehose-data/"
    _create_extended_stream_with_retry(
        firehose, stream_name, role_arn, f"arn:aws:s3:::{bucket}", prefix,
        buffering={"IntervalInSeconds": 60, "SizeInMBs": 1},
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, stream_name))
    _wait_stream_active(firehose, stream_name)

    markers = [ctx.unique_name(f"rec{i}-") for i in range(5)]
    records = [{"Data": f"{m}\n".encode()} for m in markers]
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"expected FailedPutCount == 0, got {resp['FailedPutCount']}"

    contents = _poll_for_object(s3, bucket, prefix=prefix, timeout_s=180)
    assert contents, "Firehose never delivered any object under the configured prefix"
    for obj in contents:
        assert obj["Key"].startswith(prefix), f"expected key under {prefix!r}, got {obj['Key']!r}"

    # Firehose does not keep records in order, so every record must arrive exactly once and
    # uncorrupted, in any order.
    combined = b"".join(s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read() for o in contents)
    lines = [line for line in combined.decode().splitlines() if line]
    assert sorted(lines) == sorted(markers), f"expected each of {markers} exactly once, got {lines}"


def _create_bucket(ctx: Any, s3, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "fhbatch-dst"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
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


def _create_role(ctx: Any, iam, name: str, principal: str, policy_doc: dict) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    if policy_doc:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-policy", PolicyDocument=json.dumps(policy_doc))
    return arn


def _delete_role(iam, name: str) -> None:
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_extended_stream_with_retry(
    firehose, name: str, role_arn: str, bucket_arn: str, prefix: str,
    buffering: dict, timeout_s: float = 90.0,
) -> None:
    ext_config = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": prefix,
        "BufferingHints": buffering,
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=ext_config,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "assume role" in msg:
                last_err = e
                time.sleep(5)
                continue
            raise
    assert last_err is not None, f"create_delivery_stream never attempted within {timeout_s}s"
    raise last_err


def _wait_stream_active(firehose, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)
        status = desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status == "CREATING_FAILED":
            raise AssertionError("delivery stream entered CREATING_FAILED")
        time.sleep(interval_s)
    raise AssertionError("delivery stream never became ACTIVE")


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_for_object(s3, bucket: str, prefix: str = "", timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            return contents
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
