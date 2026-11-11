"""firehose-assumes-role-with-correct-trust-policy."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-assumes-role-with-correct-trust-policy"
GROUP = "permission-boundary"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Firehose delivery stream whose destination role trusts firehose.amazonaws.com
    is accepted, transitions to ACTIVE, and actually delivers put_record data into the
    S3 destination end to end (not just a control-plane create/describe smoke test)."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, "sim2real-fh-ok-")
    role_arn = _create_role(ctx, "firehose.amazonaws.com", _s3_write_policy(bucket))

    stream_name = ctx.unique_name("sim2real-fh-ok-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": "sim2real/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_delivery_stream(ctx, stream_name))
    _wait_stream_active(firehose, stream_name)

    marker = ctx.unique_name("sim2real-marker-")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": f"{marker}\n".encode()})

    body = _poll_s3_for_marker(s3, bucket, "sim2real/", marker, timeout_s=420)
    assert marker in body, f"expected marker {marker!r} in delivered S3 object, got body={body!r}"


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, trust_service: str, permissions: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    # Teardowns run last-registered first: the inline policy goes before the role (DeleteConflict otherwise).
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _s3_write_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectAcl"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }


def _create_delivery_stream_with_retry(firehose, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = e
            time.sleep(2)
    raise AssertionError(f"create_delivery_stream never succeeded (IAM propagation?): {last_err}")


def _wait_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} never became ACTIVE (last status={status})")


def _poll_s3_for_marker(s3, bucket: str, prefix: str, marker: str, timeout_s: float = 420.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
            if marker in body:
                return body
        time.sleep(5)
    raise AssertionError(f"marker {marker} never appeared under s3://{bucket}/{prefix}")


# Inside the suite's 900 s cleanup budget; the other teardowns of the check return at once.
_STREAM_TEARDOWN_S = 600.0


def _delete_delivery_stream(ctx, name: str) -> None:
    """DeleteDeliveryStream, then poll every 2 s until DescribeDeliveryStream answers
    ResourceNotFoundException. A stream still CREATING refuses the delete with ResourceInUseException,
    which is retried; any other failure, or the deadline passing, raises."""
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    deadline = time.monotonic() + _STREAM_TEARDOWN_S
    deleted = False
    while True:
        try:
            if not deleted:
                firehose.delete_delivery_stream(DeliveryStreamName=name)
                deleted = True
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
