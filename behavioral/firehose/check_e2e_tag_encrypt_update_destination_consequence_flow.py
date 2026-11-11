"""e2e-tag-encrypt-update-destination-consequence-flow."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-tag-encrypt-update-destination-consequence-flow"
GROUP = "e2e"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Tag a stream, enable encryption and update its destination (new prefix, GZIP); a record
    put afterwards lands under the new prefix as gzip content, and nothing lands under the old
    prefix."""
    bucket_name, bucket_arn = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket_arn)
    stream_name = ctx.unique_name("sim2real-behav-fh-stream-")
    old_prefix = "orig/"
    new_prefix = "updated/"

    _create_stream_with_retry(
        ctx,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "BucketARN": bucket_arn,
            "RoleARN": role_arn,
            "Prefix": old_prefix,
            "CompressionFormat": "UNCOMPRESSED",
            "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name, timeout_s=_budget_s(ctx, 300.0))
    firehose = ctx.client("firehose")

    firehose.tag_delivery_stream(DeliveryStreamName=stream_name, Tags=[{"Key": "env", "Value": "sim2real-behav"}])
    tags = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)["Tags"]
    assert {"Key": "env", "Value": "sim2real-behav"} in tags, f"expected env=sim2real-behav tag, got {tags}"

    firehose.start_delivery_stream_encryption(DeliveryStreamName=stream_name)
    _wait_encryption_status(ctx, stream_name, "ENABLED", timeout_s=_budget_s(ctx, 180.0))

    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    version_id = desc["VersionId"]
    dest_id = desc["Destinations"][0]["DestinationId"]
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_id,
        DestinationId=dest_id,
        S3DestinationUpdate={
            "BucketARN": bucket_arn,
            "RoleARN": role_arn,
            "Prefix": new_prefix,
            "CompressionFormat": "GZIP",
            "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
        },
    )
    desc2 = _wait_version_past(ctx, stream_name, version_id, timeout_s=_budget_s(ctx, 60.0))
    if desc2["VersionId"] == version_id and _budget_spent(ctx):
        raise TimeoutError(f"VersionId advancing past {version_id!r}: the run budget ended first; not graded")
    new_version_id = desc2["VersionId"]
    assert new_version_id != version_id, f"expected VersionId to advance past {version_id!r}, still {new_version_id!r}"
    s3_desc = desc2["Destinations"][0]["S3DestinationDescription"]
    assert s3_desc["Prefix"] == new_prefix, f"expected Prefix {new_prefix!r}, got {s3_desc['Prefix']!r}"
    assert s3_desc["CompressionFormat"] == "GZIP", f"expected CompressionFormat GZIP, got {s3_desc['CompressionFormat']!r}"

    marker = ctx.unique_name("marker-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker}\n".encode()})

    key, raw_body = _wait_for_gzip_object_with_marker(ctx, bucket_name, new_prefix, marker, timeout_s=_budget_s(ctx, 600.0))
    assert key.startswith(new_prefix), f"expected delivered key under new prefix {new_prefix!r}, got {key!r}"
    assert key.endswith(".gz"), f"expected a .gz object under new prefix, got key {key!r}"
    decompressed = gzip.decompress(raw_body)
    assert marker.encode() in decompressed, f"expected marker {marker!r} in decompressed body, got {decompressed!r}"

    # The record was put after the update, so the old prefix must stay empty.
    old_objects = ctx.client("s3").list_objects_v2(Bucket=bucket_name, Prefix=old_prefix).get("Contents", [])
    assert old_objects == [], f"expected no objects under stale old prefix {old_prefix!r}, found {old_objects}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-fh-").lower()
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    return bucket_name, f"arn:aws:s3:::{bucket_name}"


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_firehose_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
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
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="FirehoseS3Access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="FirehoseS3Access"))
    return role["Arn"]


def _create_stream_with_retry(ctx, **kwargs) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _safe_delete_stream(ctx, stream_name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"stream {stream_name} entered CREATING_FAILED")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"stream {stream_name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_version_past(ctx, stream_name: str, version_id: str, timeout_s: float) -> dict:
    """Describe the stream until its VersionId differs from version_id; return the last one seen."""
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["VersionId"] != version_id or time.monotonic() >= deadline:
            return desc
        time.sleep(1)


def _wait_encryption_status(ctx, stream_name: str, expected_status: str, timeout_s: float = 180.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        status = desc.get("DeliveryStreamEncryptionConfiguration", {}).get("Status")
        if status == expected_status:
            return
        if status and status.endswith("_FAILED"):
            raise AssertionError(f"encryption entered {status}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"encryption status reaching {expected_status}: the run budget ended first; not graded")
    raise AssertionError(f"encryption status never reached {expected_status} within {timeout_s}s")


def _wait_for_gzip_object_with_marker(ctx, bucket: str, prefix: str, marker: str, timeout_s: float = 600.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            raw_body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            try:
                decompressed = gzip.decompress(raw_body)
            except OSError:
                continue
            if marker.encode() in decompressed:
                return obj["Key"], raw_body
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"a gzip object under prefix {prefix!r} in {bucket!r} containing the marker: the run budget ended first; not graded")
    raise AssertionError(f"no gzip object under prefix {prefix!r} in {bucket!r} containing marker within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
