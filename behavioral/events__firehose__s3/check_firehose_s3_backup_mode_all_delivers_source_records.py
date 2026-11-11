"""firehose-s3-backup-mode-all-delivers-source-records."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-s3-backup-mode-all-delivers-source-records"
GROUP = "delivery"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With S3BackupMode Enabled on a dynamically partitioned S3 destination, every source
    record lands twice: partitioned under the primary customer_id= prefixes and raw,
    unpartitioned, under the backup bucket prefix."""
    bucket_primary = _create_bucket(ctx, "sim2real-fh-backup-pri-")
    bucket_backup = _create_bucket(ctx, "sim2real-fh-backup-bak-")
    log_group = _create_log_group(ctx, "sim2real-fh-backup-")
    role_arn = _create_role(
        ctx,
        [
            _s3_write_statement(bucket_primary),
            _s3_write_statement(bucket_backup),
            _logs_write_statement(ctx, ctx.client("sts").get_caller_identity()["Account"], log_group),
        ],
    )

    stream_name = ctx.unique_name("sim2real-fh-backup-")
    s3_config = {
        "BucketARN": f"arn:aws:s3:::{bucket_primary}",
        "RoleARN": role_arn,
        "Prefix": "data/customer_id=!{partitionKeyFromQuery:customer_id}/",
        "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/",
        # Firehose requires BufferingHints.SizeInMBs >= 64 when Dynamic Partitioning
        # is enabled on the primary destination.
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
        "S3BackupMode": "Enabled",
        "S3BackupConfiguration": {
            "BucketARN": f"arn:aws:s3:::{bucket_backup}",
            "RoleARN": role_arn,
            "Prefix": "raw/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
        "CloudWatchLoggingOptions": {
            "Enabled": True,
            "LogGroupName": log_group,
            "LogStreamName": "DestinationDelivery",
        },
    }
    firehose = _create_delivery_stream(ctx, stream_name, s3_config)

    records = []
    for customer_id in ("x", "y"):
        for i in range(3):
            records.append(
                {"Data": (json.dumps({"customer_id": customer_id, "seq": i}) + "\n").encode("utf-8")}
            )
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"put_record_batch reported {resp['FailedPutCount']} failed puts: {resp}"

    # Primary: processed records land partitioned by customer_id.
    primary_lines: list[dict[str, Any]] = []
    for customer_id in ("x", "y"):
        prefix = f"data/customer_id={customer_id}/"
        try:
            keys = _poll_until(
                lambda p=prefix: _list_keys(ctx, bucket_primary, prefix=p),
                lambda ks: len(ks) > 0,
                timeout_s=420.0,
                interval_s=6.0,
            )
        except AssertionError:
            code = _find_error_code(ctx, log_group, "DestinationDelivery")
            raise AssertionError(f"primary delivery for {customer_id!r} never arrived; delivery error code={code!r}")
        for key in keys:
            for line in _get_bytes(ctx, bucket_primary, key).splitlines():
                if line.strip():
                    primary_lines.append(json.loads(line))

    # Backup: raw source records land unpartitioned under the backup prefix.
    def backup_probe() -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key in _list_keys(ctx, bucket_backup, prefix="raw/"):
            for line in _get_bytes(ctx, bucket_backup, key).splitlines():
                if line.strip():
                    out.append(json.loads(line))
        return out

    backup_lines = _poll_until(
        backup_probe, lambda ls: len(ls) >= len(records), timeout_s=180.0, interval_s=6.0
    )

    def _key(rec: dict[str, Any]) -> tuple[str, int]:
        return (rec["customer_id"], rec["seq"])

    sent_keys = {("x", i) for i in range(3)} | {("y", i) for i in range(3)}
    assert {_key(r) for r in primary_lines} == sent_keys, "processed/partitioned copy is missing records"
    assert {_key(r) for r in backup_lines} == sent_keys, "raw backup copy is missing records"
    # Backup keys must all sit under the single unpartitioned raw/ prefix (not customer-keyed).
    for key in _list_keys(ctx, bucket_backup, prefix="raw/"):
        assert "customer_id=" not in key, f"backup object {key!r} was unexpectedly partitioned"


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_MANAGED_TAG_KEY = "sim2real:managed"
_MANAGED_TAGS_KV = [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _MANAGED_TAGS_KV})
    except ClientError:
        pass

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


def _logs_write_statement(ctx, account_id: str, log_group: str) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": ["logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group}:*",
    }


def _create_log_group(ctx, prefix: str) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={_MANAGED_TAG_KEY: "true"})
    logs.create_log_stream(logGroupName=name, logStreamName="DestinationDelivery")

    def _cleanup() -> None:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _find_error_code(ctx, log_group: str, log_stream: str) -> str | None:
    logs = ctx.client("logs")
    try:
        resp = logs.get_log_events(logGroupName=log_group, logStreamName=log_stream, startFromHead=True)
    except ClientError:
        return None
    for event in resp.get("events", []):
        try:
            payload = json.loads(event["message"])
        except (ValueError, TypeError):
            continue
        code = payload.get("errorCode")
        if code:
            return code
    return None


def _create_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=_MANAGED_TAGS_KV,
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
                Tags=_MANAGED_TAGS_KV,
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
