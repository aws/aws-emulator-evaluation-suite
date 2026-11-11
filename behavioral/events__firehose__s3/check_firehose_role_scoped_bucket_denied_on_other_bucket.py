"""firehose-role-scoped-bucket-denied-on-other-bucket."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-role-scoped-bucket-denied-on-other-bucket"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Firehose role scoped to bucket A delivers to A but logs S3.AccessDenied and writes nothing to bucket
    B; widening its policy to cover B makes the same delivery to B succeed."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_a = _create_bucket(ctx, "sim2real-fh-scoped-a-")
    bucket_b = _create_bucket(ctx, "sim2real-fh-scoped-b-")

    log_group_a = _create_log_group(ctx, "sim2real-fh-scoped-loga-")
    log_group_b = _create_log_group(ctx, "sim2real-fh-scoped-logb-")

    role_statements = [
        _s3_write_statement(bucket_a),  # scoped ONLY to bucket_a
        _logs_write_statement(ctx, account_id, log_group_a),
        _logs_write_statement(ctx, account_id, log_group_b),
    ]
    role_arn, role_name = _create_role(ctx, role_statements)

    # Stream targeting the scoped (allowed) bucket -- positive control.
    stream_a = ctx.unique_name("sim2real-fh-scoped-a-")
    config_a = {
        "BucketARN": f"arn:aws:s3:::{bucket_a}",
        "RoleARN": role_arn,
        "Prefix": "data/",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {"Enabled": True, "LogGroupName": log_group_a, "LogStreamName": "DestinationDelivery"},
    }
    firehose_a = _create_delivery_stream(ctx, stream_a, config_a)
    firehose_a.put_record(DeliveryStreamName=stream_a, Record={"Data": b"allowed-bucket-record\n"})

    # Stream targeting a DIFFERENT bucket the role is not scoped for.
    stream_b = ctx.unique_name("sim2real-fh-scoped-b-")
    config_b = {
        "BucketARN": f"arn:aws:s3:::{bucket_b}",
        "RoleARN": role_arn,
        "Prefix": "data/",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {"Enabled": True, "LogGroupName": log_group_b, "LogStreamName": "DestinationDelivery"},
    }
    firehose_b = _create_delivery_stream(ctx, stream_b, config_b)
    firehose_b.put_record(DeliveryStreamName=stream_b, Record={"Data": b"denied-bucket-record\n"})

    # Positive control: bucket_a receives its record. Generous window: the role was just created,
    # and IAM permission propagation to firehose.amazonaws.com plus the buffering interval can
    # together exceed 180s.
    keys_a = _poll_until(
        lambda: _list_keys(ctx, bucket_a, prefix="data/"),
        lambda ks: len(ks) > 0,
        timeout_s=300.0,
        interval_s=6.0,
    )
    assert keys_a, "role failed to deliver to the bucket it IS scoped for"

    # Negative: bucket_b logs the specific denial and never receives an object.
    logged = _poll_until(
        lambda: _find_error_code(ctx, log_group_b, "DestinationDelivery"),
        lambda code: code is not None,
        timeout_s=300.0,
        interval_s=6.0,
    )
    assert logged == "S3.AccessDenied", f"expected S3.AccessDenied, got {logged!r}"
    assert _list_keys(ctx, bucket_b, prefix="data/") == [], (
        "records were delivered to a bucket the role's policy does not scope"
    )

    # Restore: widen the SAME role's policy to also cover bucket_b, then retry the
    # identical call. This isolates the earlier denial to the policy scope -- not to
    # some other misconfiguration -- because the only thing that changed is the grant.
    _put_role_policy(ctx, role_name, role_statements + [_s3_write_statement(bucket_b)])
    firehose_b.put_record(DeliveryStreamName=stream_b, Record={"Data": b"restored-bucket-record\n"})
    keys_b_after_restore = _poll_until(
        lambda: _list_keys(ctx, bucket_b, prefix="data/"),
        lambda ks: len(ks) > 0,
        timeout_s=300.0,
        interval_s=6.0,
    )
    assert keys_b_after_restore, (
        "role still could not deliver to bucket_b after its policy was widened to include it"
    )


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
    logs.create_log_group(logGroupName=name, tags={"sim2real": "true"})
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


def _create_role(ctx, policy_statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    return role["Arn"], name


def _put_role_policy(ctx, role_name: str, policy_statements: list[dict[str, Any]]) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName="access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )


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
                Tags=[{"Key": "sim2real", "Value": "true"}],
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
