"""metric-stream-start-stop-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metric-stream-start-stop-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream creates a stream already in the 'running' state; StopMetricStreams
    flips it to 'stopped' while retaining its configuration, and StartMetricStreams flips
    it back to 'running'."""
    cw = ctx.client("cloudwatch")
    firehose_arn = _create_backing_firehose(ctx)
    role_arn = _create_metric_stream_role(ctx, firehose_arn)

    stream_name = ctx.unique_name("sim2realbehavstream").replace("-", "")[:60]

    put_resp = cw.put_metric_stream(
        Name=stream_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "AWS/EC2"}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))
    assert put_resp["Arn"].endswith(stream_name)

    created = cw.get_metric_stream(Name=stream_name)
    assert created["State"] == "running", created["State"]
    assert created["FirehoseArn"] == firehose_arn

    cw.stop_metric_streams(Names=[stream_name])
    stopped = cw.get_metric_stream(Name=stream_name)
    assert stopped["State"] == "stopped", stopped["State"]
    # Configuration is retained while stopped.
    assert stopped["FirehoseArn"] == firehose_arn
    assert stopped["RoleArn"] == role_arn

    cw.start_metric_streams(Names=[stream_name])
    restarted = cw.get_metric_stream(Name=stream_name)
    assert restarted["State"] == "running", restarted["State"]


# ===== helpers =====

def _create_backing_firehose(ctx) -> str:
    """Create an S3 bucket + Firehose delivery stream that PutMetricStream can reference.

    A fabricated FirehoseArn would in fact be accepted by PutMetricStream (it is not
    eagerly resolved), but this check builds a genuine backing Firehose delivery stream
    anyway so the RoleArn it creates next is validated against a real cross-service
    target.
    """

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
    _retry_propagation(
        ctx,
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={"RoleARN": fh_role, "BucketARN": bucket_arn},
        ),
        ("InvalidArgumentException", "AccessDeniedException"),
        "creating the backing firehose delivery stream",
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

    # IAM role propagation: retry a throwaway PutMetricStream/DeleteMetricStream round trip.
    def _probe_stream() -> None:
        probe_name = ctx.unique_name("sim2real-behav-msprobe-")
        cw.put_metric_stream(
            Name=probe_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json"
        )
        cw.delete_metric_stream(Name=probe_name)

    _retry_propagation(
        ctx,
        _probe_stream,
        ("InvalidParameterValueException", "AccessDeniedException"),
        "the metric stream role becoming usable",
    )
    return role_arn


def _retry_propagation(ctx, fn, codes, what: str, timeout_s: float = 60.0):
    """Call fn(), retrying every 2 s while it raises one of the IAM propagation *codes*."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} did not succeed within {timeout_s}s: {e}") from e
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
