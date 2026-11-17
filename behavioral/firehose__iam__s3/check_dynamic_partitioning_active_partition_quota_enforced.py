"""dynamic-partitioning-active-partition-quota-enforced."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dynamic-partitioning-active-partition-quota-enforced"
GROUP = "quota"
SERVICES = ["firehose", "iam", "s3"]

_ACTIVE_PARTITION_QUOTA = 500


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Dynamic partitioning delivers up to the documented 500 active-partition quota to their
    own S3 prefixes, while the partition that would exceed it is diverted to the error prefix.

    Reference: https://docs.aws.amazon.com/general/latest/gr/fh.html
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket)
    stream = _create_delivery_stream(ctx, role_arn, bucket)
    firehose = ctx.client("firehose")

    at_quota = [_record(f"slot-{i:04d}") for i in range(_ACTIVE_PARTITION_QUOTA)]
    resp = _put_batch_with_retry(ctx, firehose, stream, at_quota)
    assert resp["FailedPutCount"] == 0, (
        f"the {len(at_quota)} records at the quota were not all accepted: {resp!r}"
    )
    over_quota = _record("slot-0500")
    resp2 = firehose.put_record_batch(DeliveryStreamName=stream, Records=[over_quota])
    assert resp2["FailedPutCount"] == 0, (
        f"the record past the quota was rejected at ingestion rather than at delivery: {resp2!r}"
    )

    want_prefixes = {f"data/slot=slot-{i:04d}/" for i in range(_ACTIVE_PARTITION_QUOTA)}
    delivered = _poll_until(
        lambda: _data_prefixes(ctx, bucket),
        lambda got: want_prefixes <= got,
        timeout_s=300,
        interval_s=10,
        description=f"all {_ACTIVE_PARTITION_QUOTA} within-quota partitions are delivered",
    )
    assert delivered == want_prefixes, (
        f"delivered partitions were {sorted(delivered)!r}, expected exactly the "
        f"{_ACTIVE_PARTITION_QUOTA} within-quota partitions"
    )

    error_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "errors/"),
        lambda ks: len(ks) > 0,
        timeout_s=300,
        interval_s=10,
        description="the partition past the quota lands under the error prefix",
    )
    assert len(error_keys) == 1, f"expected exactly one error object, got {sorted(error_keys)!r}"
    err_doc = json.loads(_get_bytes(ctx, bucket, error_keys[0]))
    assert err_doc["errorCode"] == "DynamicPartitioning.ActivePartitionsLimitExceeded", (
        f"the over-quota record was diverted with errorCode {err_doc.get('errorCode')!r}"
    )
    assert err_doc["errorMessage"] == "active-partition-count-exceeded", (
        f"the over-quota record's error object carried message {err_doc.get('errorMessage')!r}"
    )
    assert base64.b64decode(err_doc["rawData"]) == over_quota["Data"], (
        "the error object's rawData did not carry the over-quota record's original bytes"
    )

    assert not [k for k in _list_keys(ctx, bucket, "data/") if "slot-0500" in k], (
        "the over-quota partition's key leaked into the data prefix alongside the "
        "within-quota ones"
    )


def _record(slot: str) -> dict[str, Any]:
    return {"Data": (json.dumps({"slot": slot}, sort_keys=True) + "\n").encode("utf-8")}


_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-quota-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    return name


def _delete_bucket(ctx, bucket: str) -> None:
    """Empty then delete; teardown raises on failure, so the bucket must be empty first."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                deleted = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                )
                failed = deleted.get("Errors")
                if failed:
                    raise RuntimeError(f"delete_objects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-quota-role-")
    bucket_arn = f"arn:aws:s3:::{bucket}"
    statement = {
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
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="delivery",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )
    return role["Arn"]


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=name, PolicyName="delivery")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_delivery_stream(ctx, role_arn: str, bucket: str) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-quota-")
    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": "data/slot=!{partitionKeyFromQuery:slot}/",
        "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/",
        # Dynamic partitioning requires BufferingHints.SizeInMBs >= 64.
        "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
        "CompressionFormat": "UNCOMPRESSED",
        "DynamicPartitioningConfiguration": {"Enabled": True},
        "ProcessingConfiguration": {
            "Enabled": True,
            "Processors": [
                {
                    "Type": "MetadataExtraction",
                    "Parameters": [
                        {"ParameterName": "MetadataExtractionQuery", "ParameterValue": "{slot:.slot}"},
                        {"ParameterName": "JsonParsingEngine", "ParameterValue": "JQ-1.6"},
                    ],
                }
            ],
        },
    }
    deadline = time.monotonic() + 120
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if (
                code == "InvalidArgumentException"
                and "unable to assume role" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(
        lambda: _retry_not_found(
            lambda: ctx.client("firehose").delete_delivery_stream(DeliveryStreamName=name),
            "ResourceNotFoundException",
        )
    )
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=180,
        interval_s=5,
        description=f"delivery stream {name} reaches ACTIVE",
    )
    assert status == "ACTIVE", f"delivery stream {name} became {status!r} instead of ACTIVE"
    return name


def _retry_not_found(fn, *not_found: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in not_found:
            raise


def _put_batch_with_retry(ctx, firehose, stream: str, records: list[dict[str, Any]], *, timeout_s=120.0):
    """PutRecordBatch, retrying only the delivery-role propagation window at first use."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.put_record_batch(DeliveryStreamName=stream, Records=records)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ResourceNotFoundException") and (
                time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


def _list_keys(ctx, bucket: str, prefix: str) -> list[str]:
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _data_prefixes(ctx, bucket: str) -> set[str]:
    keys = _list_keys(ctx, bucket, "data/")
    out = set()
    for k in keys:
        i = k.index("/", len("data/"))
        out.add(k[: i + 1])
    return out


def _get_bytes(ctx, bucket: str, key: str) -> bytes:
    return ctx.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
