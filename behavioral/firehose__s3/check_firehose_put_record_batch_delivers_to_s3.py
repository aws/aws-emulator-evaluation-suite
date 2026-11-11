"""firehose-put-record-batch-delivers-to-s3."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-put-record-batch-delivers-to-s3"

GROUP = "data-delivery"

SERVICES = ["firehose", "s3"]

_S3_DELIVERY_ACTIONS = [
    "s3:AbortMultipartUpload",
    "s3:GetBucketLocation",
    "s3:GetObject",
    "s3:ListBucket",
    "s3:ListBucketMultipartUploads",
    "s3:PutObject",
]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]


def _provision_stream(ctx, prefix: str) -> tuple:
    """Create a bucket + Firehose delivery role + DirectPut->S3 stream; wait ACTIVE.

    Returns (firehose_client, stream_name, bucket, prefix). Cleanup is tracked LIFO
    (stream -> role -> bucket) by the harness helpers + track().
    """
    bucket = _create_bucket(ctx)
    role = _create_role(
        ctx,
        "firehose.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": _S3_DELIVERY_ACTIONS,
                    "Resource": [bucket["arn"], f"{bucket['arn']}/*"],
                }
            ],
        },
    )
    firehose = ctx.client("firehose")
    name = ctx.unique_name("dstream-")
    create_kwargs = dict(
        DeliveryStreamName=name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": role["arn"],
            "BucketARN": bucket["arn"],
            "Prefix": prefix,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=_MANAGED_TAGS,
    )
    # Firehose assumes the delivery role at create time; a freshly-created role can lose the
    # IAM propagation race ("Firehose is unable to assume role"). Retry that transient case
    # to a deadline.
    deadline = time.monotonic() + 90
    while True:
        try:
            firehose.create_delivery_stream(**create_kwargs)
            break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            msg = e.response.get("Error", {}).get("Message", "")
            if (
                code == "InvalidArgumentException"
                and "assume role" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, name))
    _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s == "ACTIVE",
        ctx=ctx,
        timeout_s=120,
        interval_s=2,
        description="delivery stream reaches ACTIVE",
    )
    return firehose, name, bucket, prefix


def _delivered_bodies(ctx, bucket: str, prefix: str) -> list[str]:
    """Poll S3 under prefix until at least one delivered object appears; return their bodies.

    Firehose's S3 buffer flushes on a 60s minimum interval, so this waits up to ~4 min.
    """
    s3 = ctx.client("s3")
    objs = _poll_until(
        lambda: s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", []),
        lambda c: len(c) > 0,
        ctx=ctx,
        timeout_s=240,
        interval_s=2,
        description="Firehose object lands in S3",
    )
    return [
        s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read().decode("utf-8")
        for o in objs
    ]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """PutRecordBatch delivers every record to S3; all markers are present in the flushed object(s)."""
    firehose, name, bucket, prefix = _provision_stream(ctx, "batch/")
    markers = [ctx.unique_name(f"b{i}-") for i in range(5)]
    records = [
        {"Data": (json.dumps({"marker": mk, "i": i}) + "\n").encode("utf-8")}
        for i, mk in enumerate(markers)
    ]
    resp = firehose.put_record_batch(DeliveryStreamName=name, Records=records)
    assert resp.get("FailedPutCount", 0) == 0, (
        f"batch had failures: {resp.get('FailedPutCount')}"
    )

    joined = "".join(_delivered_bodies(ctx, bucket["name"], "batch/"))
    missing = [mk for mk in markers if mk not in joined]
    assert not missing, f"{len(missing)} batch records never landed in S3: {missing}"


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _create_role(ctx, trust_service, inline_policy=None):
    """Create an IAM role (Path=/sim2real/) and register a policy-detach-then-delete cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-xsvc-role-{trust_service.split('.')[0]}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every inline/attached policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _delete_stream_and_wait(firehose, name: str, timeout_s: float = 300.0, **delete_kwargs) -> None:
    """Delete the delivery stream and poll until it is gone: it keeps listing while DELETING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.delete_delivery_stream(DeliveryStreamName=name, **delete_kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"delivery stream {name!r} still exists {timeout_s:.0f}s after DeleteDeliveryStream"
    )


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, ctx=None, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    left = ctx.time_left() if ctx is not None else None
    if left is not None:
        timeout_s = min(timeout_s, left)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """S3 buckets must be emptied before deletion — a raw delete_bucket on a non-empty bucket fails
    with BucketNotEmpty and (since teardown swallows errors) leaks the bucket. Purge objects AND all
    versions/delete-markers (versioning may be on), then delete."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint; every other region requires
        # one — an S3 API quirk, not a region pin on this check's own target region.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
