"""metric-stream-lastupdate-timestamp-reflects-start-stop."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "metric-stream-lastupdate-timestamp-reflects-start-stop"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMetricStream's State/LastUpdateDate advance every time Start/StopMetricStreams is
    called, so the timestamp is a faithful signal of state-change recency (not a static
    creation-time value)."""
    cw_probe = ctx.client("cloudwatch")
    bogus_name = ctx.unique_name("sim2real-behav-ms-missing-")
    error = _error(lambda: cw_probe.get_metric_stream(Name=bogus_name))
    assert error == ("ResourceNotFoundException", ""), (
        f"GetMetricStream on a nonexistent metric stream name returned {error!r}, "
        "expected that exact ResourceNotFoundException"
    )

    cw = ctx.client("cloudwatch")
    firehose_role_arn = _create_role(ctx, "firehose.amazonaws.com", "fh-role")
    bucket, bucket_arn = _create_bucket(ctx)
    _put_inline_policy(
        ctx,
        firehose_role_arn.split("/")[-1],
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
    delivery_arn = _create_delivery_stream(ctx, firehose_role_arn, bucket_arn)

    stream_role_arn = _create_role(ctx, "streams.metrics.cloudwatch.amazonaws.com", "ms-role")
    _put_inline_policy(
        ctx,
        stream_role_arn.split("/")[-1],
        "firehose-write",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": delivery_arn,
                }
            ],
        },
    )

    stream_name = ctx.unique_name("sim2real-behav-ms-")
    _create_metric_stream_with_retry(cw, stream_name, delivery_arn, stream_role_arn)
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    desc0 = cw.get_metric_stream(Name=stream_name)
    assert desc0["State"] == "running", f"expected new metric stream to be running, got {desc0['State']!r}"
    t0 = desc0["LastUpdateDate"]

    cw.stop_metric_streams(Names=[stream_name])
    t1 = _poll_metric_stream_state(cw, stream_name, "stopped")
    assert t1 > t0, "LastUpdateDate did not advance after StopMetricStreams"

    cw.start_metric_streams(Names=[stream_name])
    t2 = _poll_metric_stream_state(cw, stream_name, "running")
    assert t2 > t1, "LastUpdateDate did not advance after StartMetricStreams"


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_role(ctx, service_principal: str, prefix: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-behav-{prefix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return resp["Role"]["Arn"]


def _put_inline_policy(ctx, role_name: str, policy_name: str, doc: dict) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ms-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _create_delivery_stream(ctx, role_arn: str, bucket_arn: str) -> str:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-ms-")
    # IAM role trust propagation to Firehose is eventually consistent; retry the actual
    # create call on the specific error Firehose raises while it cannot yet assume the
    # role, rather than sleeping a fixed guess before the first attempt.
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidArgumentException" or "assume role" not in str(exc):
                raise
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"create_delivery_stream {name} never succeeded: {last_err}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    deadline = time.monotonic() + 120
    arn = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        arn = desc["DeliveryStreamARN"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return arn
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE")


def _create_metric_stream_with_retry(cw, name: str, firehose_arn: str, role_arn: str) -> None:
    # IAM role trust/permission propagation to a cross-service assumable role is eventually
    # consistent; poll the actual create call rather than sleeping a fixed guess.
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(
                Name=name,
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            return
        except Exception as exc:  # noqa: BLE001 - retry on any propagation-shaped failure
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"put_metric_stream never succeeded: {last_err}")


def _poll_metric_stream_state(cw, name: str, expected_state: str):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        desc = cw.get_metric_stream(Name=name)
        if desc["State"] == expected_state:
            return desc["LastUpdateDate"]
        time.sleep(2)
    raise AssertionError(f"metric stream {name} never reached state {expected_state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
