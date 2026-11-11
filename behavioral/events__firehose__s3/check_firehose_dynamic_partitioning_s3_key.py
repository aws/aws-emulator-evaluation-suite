"""firehose-dynamic-partitioning-s3-key."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-dynamic-partitioning-s3-key"
GROUP = "data-format"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Dynamic partitioning keys derived from a JQ expression against each record's
    JSON body route records to distinct !{partitionKeyFromQuery:...} S3 prefixes."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, [_s3_write_statement(bucket)])
    stream_name = ctx.unique_name("sim2real-fh-dynpart-")
    s3_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": role_arn,
        "Prefix": "data/customer_id=!{partitionKeyFromQuery:customer_id}/",
        "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/",
        # Firehose requires BufferingHints.SizeInMBs >= 64 when Dynamic Partitioning
        # is enabled.
        "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
        "DynamicPartitioningConfiguration": {
            "Enabled": True,
            "RetryOptions": {"DurationInSeconds": 60},
        },
        "ProcessingConfiguration": {
            "Enabled": True,
            "Processors": [
                {
                    "Type": "MetadataExtraction",
                    "Parameters": [
                        {"ParameterName": "MetadataExtractionQuery", "ParameterValue": "{customer_id:.customer_id}"},
                        {"ParameterName": "JsonParsingEngine", "ParameterValue": "JQ-1.6"},
                    ],
                }
            ],
        },
    }
    firehose = _create_delivery_stream(ctx, stream_name, s3_config)

    records = []
    for customer_id in ("alpha", "beta"):
        for i in range(5):
            records.append(
                {"Data": (json.dumps({"customer_id": customer_id, "seq": i}) + "\n").encode("utf-8")}
            )
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, (
        f"expected all {len(records)} records accepted, got FailedPutCount={resp['FailedPutCount']}"
    )

    expected_prefixes = {f"data/customer_id={c}/" for c in ("alpha", "beta")}
    all_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, prefix="data/"),
        lambda ks: expected_prefixes <= _partition_prefixes(ks),
        timeout_s=260.0,
        interval_s=10.0,
    )
    by_prefix: dict[str, list[str]] = {}
    for key in all_keys:
        by_prefix.setdefault(key[: key.index("/", len("data/customer_id=")) + 1], []).append(key)

    for customer_id in ("alpha", "beta"):
        prefix = f"data/customer_id={customer_id}/"
        found_ids = set()
        for key in by_prefix.get(prefix, []):
            body = _get_bytes(ctx, bucket, key)
            for line in body.splitlines():
                if line.strip():
                    found_ids.add(json.loads(line)["customer_id"])
        assert found_ids == {customer_id}, (
            f"prefix {prefix!r} contained records for {found_ids}, expected only {customer_id!r}"
        )

    error_keys = _list_keys(ctx, bucket, prefix="errors/")
    assert error_keys == [], f"well-formed records unexpectedly landed under errors/: {error_keys}"


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-dynpart-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this is an S3 API quirk, not an assumption about which region the check runs in.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup() -> None:
        _empty_bucket(ctx, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})


def _s3_write_statement(bucket: str) -> dict[str, Any]:
    return {
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


def _create_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=name, PolicyName="access")
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _wait_stream_active(firehose, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE")


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_delivery_stream(ctx, name: str, s3_config: dict[str, Any], timeout_s: float = 150.0):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"create_delivery_stream never succeeded: {last_err}")
    ctx.on_cleanup(lambda: _delete_stream(firehose, name))
    _wait_stream_active(firehose, name)
    return firehose


def _partition_prefixes(keys: list[str]) -> set[str]:
    return {
        k[: k.index("/", len("data/customer_id=")) + 1]
        for k in keys
        if k.startswith("data/customer_id=") and "/" in k[len("data/customer_id="):]
    }


def _list_keys(ctx, bucket: str, prefix: str = "") -> list[str]:
    s3 = ctx.client("s3")
    keys: list[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _get_bytes(ctx, bucket: str, key: str) -> bytes:
    s3 = ctx.client("s3")
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
