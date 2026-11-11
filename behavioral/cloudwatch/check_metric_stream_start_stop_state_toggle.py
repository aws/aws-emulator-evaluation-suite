"""metric-stream-start-stop-state-toggle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-stream-start-stop-state-toggle"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metric stream is created in the 'running' state; StopMetricStreams and
    StartMetricStreams toggle its State as seen via GetMetricStream."""
    cw = ctx.client("cloudwatch")

    bucket, bucket_arn = _create_bucket(ctx)
    fh_role_name, fh_role_arn = _create_role(ctx, "firehose.amazonaws.com")
    _put_role_policy(
        ctx,
        fh_role_name,
        "s3-write",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                }
            ],
        },
    )
    firehose_arn = _create_delivery_stream(ctx, fh_role_arn, bucket_arn)

    ms_role_name, ms_role_arn = _create_role(ctx, "streams.metrics.cloudwatch.amazonaws.com")
    _put_role_policy(
        ctx,
        ms_role_name,
        "firehose-write",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": firehose_arn,
                }
            ],
        },
    )

    name = ctx.unique_name("sim2real-mstream-")
    _put_metric_stream_with_retry(ctx, name, firehose_arn, ms_role_arn)
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))

    _poll_metric_stream_state(ctx, name, "running", timeout_s=60.0)
    created = cw.get_metric_stream(Name=name)
    assert created["FirehoseArn"] == firehose_arn, (
        f"expected FirehoseArn {firehose_arn!r} on the new stream, got {created['FirehoseArn']!r}"
    )
    assert created["RoleArn"] == ms_role_arn, (
        f"expected RoleArn {ms_role_arn!r} on the new stream, got {created['RoleArn']!r}"
    )

    cw.stop_metric_streams(Names=[name])
    _poll_metric_stream_state(ctx, name, "stopped", timeout_s=60.0)
    stopped = cw.get_metric_stream(Name=name)
    assert stopped["FirehoseArn"] == firehose_arn, (
        f"expected FirehoseArn retained while stopped, got {stopped['FirehoseArn']!r}"
    )
    assert stopped["RoleArn"] == ms_role_arn, (
        f"expected RoleArn retained while stopped, got {stopped['RoleArn']!r}"
    )

    cw.start_metric_streams(Names=[name])
    _poll_metric_stream_state(ctx, name, "running", timeout_s=60.0)
    restarted = cw.get_metric_stream(Name=name)
    assert restarted["FirehoseArn"] == firehose_arn, (
        f"expected FirehoseArn retained after restart, got {restarted['FirehoseArn']!r}"
    )
    assert restarted["RoleArn"] == ms_role_arn, (
        f"expected RoleArn retained after restart, got {restarted['RoleArn']!r}"
    )


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-cwms-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _create_role(ctx, trust_principal: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, resp["Role"]["Arn"]


def _put_role_policy(ctx, role_name: str, policy_name: str, policy_doc: dict[str, Any]) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_delivery_stream(ctx, role_arn: str, bucket_arn: str) -> str:
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-fh-")

    deadline = time.monotonic() + 120.0
    last_err = None
    created = False
    while time.monotonic() < deadline:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
            )
            created = True
            break
        except ClientError as exc:  # IAM role propagation delay -- Firehose can't yet assume it
            last_err = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"create_delivery_stream never succeeded (IAM propagation?): {last_err}")
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))

    deadline = time.monotonic() + 120.0
    arn = None
    status = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            arn = desc["DeliveryStreamARN"]
            break
        time.sleep(3)
    if arn is None:
        raise AssertionError(f"firehose delivery stream never became ACTIVE, last status={status!r}")
    return arn


def _put_metric_stream_with_retry(ctx, name: str, firehose_arn: str, role_arn: str, timeout_s: float = 90.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cw.put_metric_stream(Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json")
        except ClientError as exc:  # IAM role propagation delay
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"put_metric_stream never succeeded (IAM propagation?): {last_err}")


def _poll_metric_stream_state(ctx, name: str, expected: str, timeout_s: float, interval_s: float = 3.0) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_metric_stream(Name=name)["State"]
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"metric stream {name!r} never reached state {expected!r} within {timeout_s}s, last seen {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
