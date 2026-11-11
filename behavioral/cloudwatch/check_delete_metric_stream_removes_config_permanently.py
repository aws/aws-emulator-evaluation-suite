"""delete-metric-stream-removes-config-permanently."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-metric-stream-removes-config-permanently"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stopped stream stays retrievable, but after DeleteMetricStream GetMetricStream fails with
    ResourceNotFoundException and the name is immediately reusable by PutMetricStream."""
    cw = ctx.client("cloudwatch")
    firehose_arn = _create_backing_firehose(ctx)
    role_arn = _create_metric_stream_role(ctx, firehose_arn)

    stream_name = ctx.unique_name("sim2realbehavdelstream").replace("-", "")[:60]

    cw.put_metric_stream(
        Name=stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    cw.stop_metric_streams(Names=[stream_name])
    stopped = cw.get_metric_stream(Name=stream_name)
    assert stopped["State"] == "stopped", (
        f"expected StopMetricStreams to leave the config retrievable with State='stopped', "
        f"got {stopped['State']!r}"
    )

    cw.delete_metric_stream(Name=stream_name)

    code, message = _error(lambda: cw.get_metric_stream(Name=stream_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = ""  # real AWS returns an empty Message for this code
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The name is genuinely freed, not merely soft-deleted: it can be reused immediately.
    cw.put_metric_stream(
        Name=stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_metric_stream(ctx, stream_name))
    recreated = cw.get_metric_stream(Name=stream_name)
    assert recreated["State"] == "running", (
        f"expected the freed name to be reusable by a fresh PutMetricStream, got "
        f"State={recreated['State']!r}"
    )
    cw.delete_metric_stream(Name=stream_name)


def _safe_delete_metric_stream(ctx, name: str) -> None:
    """DeleteMetricStream of an already-deleted name succeeds, so any error is a real failure."""
    ctx.client("cloudwatch").delete_metric_stream(Name=name)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _create_backing_firehose(ctx) -> str:
    """Create an S3 bucket and an ACTIVE Firehose delivery stream; return its ARN.
    PutMetricStream rejects a nonexistent FirehoseArn, so a real stream is required."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket_name = ctx.unique_name("sim2real-behav-mstream-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    fh_role_name = ctx.unique_name("sim2real-behav-fhrole-")
    fh_role = iam.create_role(
        RoleName=fh_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    iam.put_role_policy(
        RoleName=fh_role_name,
        PolicyName="s3-write",
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    _retry_on(
        ctx,
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={"RoleARN": fh_role, "BucketARN": bucket_arn},
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ),
        ("InvalidArgumentException", "AccessDeniedException"),
        "could not create backing firehose delivery stream",
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    deadline = time.monotonic() + 120
    arn = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(3)
    if arn is None:
        raise AssertionError("firehose delivery stream never became ACTIVE")
    return arn


def _create_metric_stream_role(ctx, firehose_arn: str) -> str:
    iam = ctx.client("iam")
    cw = ctx.client("cloudwatch")
    role_name = ctx.unique_name("sim2real-behav-msrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="firehose-put",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="firehose-put"))

    # IAM role propagation: retry a throwaway PutMetricStream until the new role is accepted.
    def _probe_stream():
        probe_name = ctx.unique_name("sim2real-behav-msprobe-")
        cw.put_metric_stream(
            Name=probe_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json"
        )
        cw.delete_metric_stream(Name=probe_name)

    _retry_on(
        ctx,
        _probe_stream,
        ("InvalidParameterValueException", "AccessDeniedException"),
        "metric stream role never became usable",
    )
    return role_arn


def _retry_on(ctx, fn, codes, what, timeout_s=60.0):
    """Call fn() until it succeeds, retrying only `codes` (IAM propagation) every 2 s to the deadline."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what}: {e}") from e
        time.sleep(2)


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
