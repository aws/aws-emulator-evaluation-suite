"""start-metric-streams-partial-invalid-name-is-silently-ignored."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "start-metric-streams-partial-invalid-name-is-silently-ignored"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams on a batch of one stopped stream and one unknown name succeeds and starts
    the stream; the unknown name is ignored and stays ResourceNotFoundException on GetMetricStream.
    """
    cw = ctx.client("cloudwatch")
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    firehose_arn = _create_firehose_stream(ctx, role_arn, bucket)
    ms_role_arn = _create_metric_stream_role(ctx, firehose_arn)

    stream_name = ctx.unique_name("sim2real-cw-partial-stream-")
    _retry_until_ready(
        lambda: cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=ms_role_arn,
            OutputFormat="json",
            Tags=[{"Key": "sim2real-owner", "Value": stream_name}],
        )
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    cw.stop_metric_streams(Names=[stream_name])
    _poll_until(lambda: cw.get_metric_stream(Name=stream_name)["State"] == "stopped", timeout_s=30, interval_s=3)

    bogus_name = ctx.unique_name("sim2real-cw-bogus-stream-")

    bogus_code, bogus_message = _client_error(lambda: cw.get_metric_stream(Name=bogus_name))
    assert bogus_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown stream, got {bogus_code}: {bogus_message!r}"
    )
    assert bogus_message == "", bogus_message

    # The docs' "all or nothing" rule covers permission failures, not nonexistent names.
    cw.start_metric_streams(Names=[stream_name, bogus_name])

    _poll_until(lambda: cw.get_metric_stream(Name=stream_name)["State"] == "running", timeout_s=30, interval_s=3)
    state_after = cw.get_metric_stream(Name=stream_name)["State"]
    assert state_after == "running", f"the valid stream in the mixed batch did not start: {state_after}"

    bogus_code_after, bogus_message_after = _client_error(lambda: cw.get_metric_stream(Name=bogus_name))
    assert bogus_code_after == "ResourceNotFoundException", (
        f"expected the unknown name to remain nonexistent after StartMetricStreams, "
        f"got {bogus_code_after}: {bogus_message_after!r}"
    )
    assert bogus_message_after == "", bogus_message_after


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


def _poll_until(predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(interval_s)
    raise AssertionError("condition was not met within the timeout window")


def _retry_until_ready(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise last_err


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cw-mstream-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": name}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _delete_role_quiet(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_firehose_role(ctx, bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cw-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-owner", "Value": role_name}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket", "s3:AbortMultipartUpload", "s3:GetObject"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_metric_stream_role(ctx, firehose_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cw-ms-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-owner", "Value": role_name}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["firehose:PutRecord", "firehose:PutRecordBatch", "firehose:DescribeDeliveryStream"],
                "Resource": firehose_arn,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="firehose-access", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_firehose_stream(ctx, role_arn, bucket_name):
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-cw-fh-")

    def _create():
        fh.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket_name}",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "sim2real-owner", "Value": name}],
        )

    _retry_until_ready(_create, timeout_s=90)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))

    deadline = time.monotonic() + 120
    arn = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(5)
    if arn is None:
        raise AssertionError("firehose delivery stream never became ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
