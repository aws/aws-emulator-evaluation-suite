"""op-contract-startMetricStreams-all-bogus-batch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-startMetricStreams-all-bogus-batch"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams tolerates unknown names: an all-bogus batch returns 200 and leaves a real
    stopped stream stopped, while naming the real stream alone still starts it."""
    cw = ctx.client("cloudwatch")
    stream_name, _firehose_arn = _create_running_metric_stream(ctx)

    cw.stop_metric_streams(Names=[stream_name])
    stopped = _poll_until(
        lambda: cw.get_metric_stream(Name=stream_name)["State"],
        lambda s: s == "stopped",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert stopped == "stopped", f"expected 'stopped', got {stopped!r}"

    bogus_only = ctx.unique_name("sim2real-cwmsx-missing-")
    resp = cw.start_metric_streams(Names=[bogus_only])
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected an all-bogus StartMetricStreams batch to be accepted (200), got {status}"
    assert cw.get_metric_stream(Name=stream_name)["State"] == "stopped", (
        "an all-bogus StartMetricStreams batch must not affect an unrelated real stream"
    )

    cw.start_metric_streams(Names=[stream_name])
    running = _poll_until(
        lambda: cw.get_metric_stream(Name=stream_name)["State"],
        lambda s: s == "running",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert running == "running", f"expected 'running', got {running!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {result!r}")


def _retry(fn, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    if last_exc is not None:
        raise last_exc
    raise AssertionError("retry loop exited without success or exception")


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_running_metric_stream(ctx):
    """Create an S3-backed Firehose stream and a running metric stream; return (name, firehose_arn)."""
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2real-cwmsx-start-").lower().replace("_", "-")
    stream_name = ctx.unique_name("sim2real-cwmsx-start-")
    firehose_role_name = ctx.unique_name("sim2real-cwmsx-start-fh-role-")
    cw_role_name = ctx.unique_name("sim2real-cwmsx-start-cw-role-")

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    fh_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    fh_role = iam.create_role(RoleName=firehose_role_name, AssumeRolePolicyDocument=json.dumps(fh_trust))["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, firehose_role_name))
    iam.put_role_policy(
        RoleName=firehose_role_name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:AbortMultipartUpload",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:ListBucketMultipartUploads",
                            "s3:PutObject",
                        ],
                        "Resource": [bucket_arn, bucket_arn + "/*"],
                    }
                ],
            }
        ),
    )

    _retry(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={"RoleARN": fh_role["Arn"], "BucketARN": bucket_arn},
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    description = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert description is not None, "firehose delivery stream never became ACTIVE"
    firehose_arn = description["DeliveryStreamARN"]

    cw_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    cw_role = iam.create_role(RoleName=cw_role_name, AssumeRolePolicyDocument=json.dumps(cw_trust))["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehose-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch", "firehose:DescribeDeliveryStream"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )

    _retry(
        lambda: cw.put_metric_stream(
            Name=stream_name, FirehoseArn=firehose_arn, RoleArn=cw_role["Arn"], OutputFormat="json"
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    return stream_name, firehose_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
