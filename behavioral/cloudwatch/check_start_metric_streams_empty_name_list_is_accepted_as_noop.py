"""start-metric-streams-empty-name-list-is-accepted-as-noop."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-metric-streams-empty-name-list-is-accepted-as-noop"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams with an empty Names list succeeds as a no-op and leaves a stopped stream
    stopped; the same call naming that stream starts it."""
    cw = ctx.client("cloudwatch")
    stream_name = _create_stopped_metric_stream(ctx)

    baseline_state = cw.get_metric_stream(Name=stream_name)["State"]
    assert baseline_state == "stopped"

    # An empty Names list is accepted: a refusal raises ClientError and fails the check.
    cw.start_metric_streams(Names=[])

    state_after_noop = cw.get_metric_stream(Name=stream_name)["State"]
    assert state_after_noop == "stopped", (
        f"stream transitioned to {state_after_noop!r} from an empty-list StartMetricStreams call"
    )


    # Positive control: the same call with a real name starts the stream.
    cw.start_metric_streams(Names=[stream_name])
    final_state = _poll_until(
        lambda: cw.get_metric_stream(Name=stream_name)["State"],
        lambda state: state == "running",
        timeout_s=60,
    )
    assert final_state == "running"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _create_stopped_metric_stream(ctx) -> str:
    """Create a metric stream on a real S3 + Firehose + IAM chain, stop it, and return its name.

    Cleanup is LIFO, so the stream is deleted before the delivery stream and roles it uses."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")
    cw = ctx.client("cloudwatch")

    bucket_name = ctx.unique_name("sim2real-cwms-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    firehose_role_name = ctx.unique_name("sim2real-cwms-fh-")
    firehose_role_arn = iam.create_role(
        RoleName=firehose_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, firehose_role_name))
    iam.put_role_policy(
        RoleName=firehose_role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )

    delivery_stream_name = ctx.unique_name("sim2real-cwms-ds-")
    delivery_stream_arn = _create_delivery_stream_with_retry(
        firehose, delivery_stream_name, firehose_role_arn, bucket_arn, CHECK
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=delivery_stream_name))
    _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=delivery_stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=180,
        interval_s=5,
    )

    cw_role_name = ctx.unique_name("sim2real-cwms-cw-")
    cw_role_arn = iam.create_role(
        RoleName=cw_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehose-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "firehose:PutRecord",
                            "firehose:PutRecordBatch",
                            "firehose:DescribeDeliveryStream",
                        ],
                        "Resource": delivery_stream_arn,
                    }
                ],
            }
        ),
    )

    stream_name = ctx.unique_name("sim2real-cwms-")
    _create_metric_stream_with_retry(cw, stream_name, delivery_stream_arn, cw_role_arn, CHECK)
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    cw.stop_metric_streams(Names=[stream_name])
    _poll_until(
        lambda: cw.get_metric_stream(Name=stream_name)["State"],
        lambda state: state == "stopped",
        timeout_s=60,
    )
    return stream_name


def _create_delivery_stream_with_retry(firehose, name, role_arn, bucket_arn, check_name):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
                Tags=[{"Key": "sim2real-check", "Value": check_name}],
            )
            return resp["DeliveryStreamARN"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create delivery stream (IAM propagation?): {last_exc}")


def _create_metric_stream_with_retry(cw, name, firehose_arn, role_arn, check_name):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(
                Name=name,
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
                Tags=[{"Key": "sim2real-check", "Value": check_name}],
            )
            return
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("InvalidParameterValueException", "InvalidParameterValue"):
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create metric stream (IAM propagation?): {last_exc}")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
