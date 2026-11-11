"""start-metric-streams-nonexistent-name-silently-ignored."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-metric-streams-nonexistent-name-silently-ignored"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams naming one stopped stream and one that does not exist succeeds with no
    Failures key and starts the real stream; GetMetricStream on the missing name still answers
    ResourceNotFoundException with an empty message."""
    cw = ctx.client("cloudwatch")
    prereqs = _create_metric_stream_prereqs(ctx)

    name = ctx.unique_name("sim2real-mstream-start-")
    _put_metric_stream_with_retry(cw, name, prereqs["firehose_arn"], prereqs["cw_role_arn"])
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))

    # New streams start "running"; stop it so Start has an observable transition to make.
    cw.stop_metric_streams(Names=[name])
    _poll_state(cw, name, "stopped")

    missing_name = ctx.unique_name("sim2real-mstream-missing-")

    # --- The mixed batch (one real name + one nonexistent name) does NOT raise
    # and does NOT surface a per-item Failures list -- it is not the all-or-
    # nothing / per-item-reporting shape that permission-denied batches use.
    resp = cw.start_metric_streams(Names=[name, missing_name])
    assert "Failures" not in resp, f"unexpected Failures in response: {resp}"

    # Effect present: the real stream is started despite the nonexistent sibling.
    _poll_state(cw, name, "running")

    # --- A batch containing ONLY a nonexistent name is equally accepted with
    # no error and no failure reporting -- CloudWatch treats a missing name as
    # a no-op rather than a validation failure.
    resp2 = cw.start_metric_streams(Names=[missing_name])
    assert "Failures" not in resp2, f"unexpected Failures in response: {resp2}"

    # A subsequent GetMetricStream for the nonexistent name still reports
    # ResourceNotFound -- the earlier no-op Start call did not fabricate it.
    try:
        got = cw.get_metric_stream(Name=missing_name)
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    else:
        raise AssertionError(f"expected GetMetricStream on a nonexistent name to be refused, got {got!r}")
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}: {message!r}"
    assert message == "", message


def _put_metric_stream_with_retry(cw, name, firehose_arn, role_arn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cw.put_metric_stream(Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json")
        except ClientError as exc:  # IAM role trust-policy propagation delay
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"put_metric_stream never succeeded (IAM propagation?): {last_err}")


def _poll_state(cw, name, expected_state, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_metric_stream(Name=name)["State"]
        if last == expected_state:
            return
        time.sleep(interval_s)
    raise AssertionError(f"metric stream {name} never reached state {expected_state!r} (last={last!r})")


def _create_metric_stream_prereqs(ctx) -> dict:
    """Provision a real S3-backed Firehose delivery stream plus the two IAM
    roles needed for CloudWatch -> Firehose -> S3, all in the caller's own
    account, so PutMetricStream/Start/StopMetricStreams can be exercised end
    to end."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    region = ctx.region

    bucket = ctx.unique_name("sim2real-mstream-dst2-").lower()
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    firehose_role_name = ctx.unique_name("sim2real-mstream-fh-role2-")
    firehose_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    firehose_role = iam.create_role(
        RoleName=firehose_role_name, AssumeRolePolicyDocument=json.dumps(firehose_trust)
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=firehose_role_name))
    firehose_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}],
    }
    iam.put_role_policy(
        RoleName=firehose_role_name, PolicyName="s3-write", PolicyDocument=json.dumps(firehose_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=firehose_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-mstream-fh2-")
    firehose_arn = _create_delivery_stream_with_retry(
        ctx, firehose, stream_name, bucket, firehose_role["Arn"]
    )

    cw_role_name = ctx.unique_name("sim2real-mstream-cw-role2-")
    cw_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    cw_role = iam.create_role(RoleName=cw_role_name, AssumeRolePolicyDocument=json.dumps(cw_trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=cw_role_name))
    cw_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": firehose_arn}],
    }
    iam.put_role_policy(RoleName=cw_role_name, PolicyName="firehose-write", PolicyDocument=json.dumps(cw_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-write"))

    return {"firehose_arn": firehose_arn, "cw_role_arn": cw_role["Arn"], "bucket": bucket}


def _create_delivery_stream_with_retry(ctx, firehose, stream_name, bucket, role_arn, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                },
            )
            break
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("InvalidArgumentException", "AccessDeniedException"):
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create Firehose delivery stream: {last_exc}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    return _wait_delivery_stream_active(firehose, stream_name)


def _wait_delivery_stream_active(firehose, stream_name, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"Firehose delivery stream {stream_name} never became ACTIVE")


def _empty_and_delete_bucket(s3, bucket) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
