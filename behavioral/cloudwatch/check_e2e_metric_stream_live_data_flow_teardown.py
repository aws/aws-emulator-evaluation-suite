"""e2e-metric-stream-live-data-flow-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-metric-stream-live-data-flow-teardown"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Metric stream lifecycle: create -> start -> data flows -> stop -> delete -> gone.

    The claim is that data actually moves through Firehose into S3, not merely that
    CloudWatch's own metric catalog accepted it.
    """
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-cwms-").lower().replace("_", "-")
    stream_name = ctx.unique_name("sim2real-mstream-")
    delivery_name = ctx.unique_name("sim2real-fh-")
    firehose_role_name = ctx.unique_name("sim2real-fhrole-")
    ms_role_name = ctx.unique_name("sim2real-msrole-")
    namespace = ctx.unique_name("Sim2Real/MetricStream")
    metric_name = "LiveDataFlow"
    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    _create_bucket(ctx, s3, bucket, resource_tags)

    firehose_role_arn = _create_role(
        ctx,
        iam,
        firehose_role_name,
        "firehose.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:*"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
        resource_tags,
    )

    delivery_arn = _create_delivery_stream(ctx, firehose, delivery_name, firehose_role_arn, bucket, resource_tags)

    ms_role_arn = _create_role(
        ctx,
        iam,
        ms_role_name,
        "streams.metrics.cloudwatch.amazonaws.com",
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
        resource_tags,
    )

    # IAM roles are eventually consistent for cross-service assume-role checks; retry.
    stream_arn = None
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cw.put_metric_stream(
                Name=stream_name,
                FirehoseArn=delivery_arn,
                RoleArn=ms_role_arn,
                OutputFormat="json",
                Tags=resource_tags,
            )
            stream_arn = resp["Arn"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] in (
                "InvalidParameterValueException",
                "ValidationException",
            ):
                time.sleep(3)
                continue
            raise
    if stream_arn is None:
        raise AssertionError(f"PutMetricStream never succeeded: {last_err}")
    ctx.on_cleanup(lambda: _delete_metric_stream_ignore(cw, stream_name))

    assert stream_arn.endswith(stream_name)

    cw.start_metric_streams(Names=[stream_name])

    def _get_stream():
        return cw.get_metric_stream(Name=stream_name)

    running = _poll_until(lambda: _get_stream(), lambda r: r["State"] == "running", timeout_s=30)
    assert running["State"] == "running"
    assert running["FirehoseArn"] == delivery_arn
    assert running["RoleArn"] == ms_role_arn

    # The claim under test is that the metric STREAM moves data -- CloudWatch's own
    # ListMetrics catalog would show this datum even if FirehoseArn/RoleArn were wired to
    # nothing, since PutMetricData/ListMetrics never touch Firehose. The only read that can
    # tell "the stream delivers" apart from "the stream config was merely accepted" is the
    # destination the stream actually writes to: the S3 objects Firehose buffers and flushes.
    marker_value = 4_242.0

    def _find_delivered_record():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                for line in body.splitlines():
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if record.get("namespace") != namespace or record.get("metric_name") != metric_name:
                        continue
                    values = record.get("value", {})
                    if any(
                        isinstance(v, (int, float)) and abs(v - marker_value) < 1e-6
                        for v in values.values()
                    ):
                        return record
        return None

    # 600 s: the first metric-stream object can take that long to reach S3 on AWS.
    left = ctx.time_left()
    deadline = time.monotonic() + (600.0 if left is None else min(600.0, left))
    delivered = None
    while time.monotonic() < deadline:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": marker_value, "Unit": "Count"}],
        )
        time.sleep(5.0)
        delivered = _find_delivered_record()
        if delivered is not None:
            break
    if delivered is None:
        raise AssertionError(
            f"no Firehose-delivered S3 record for {namespace}/{metric_name}={marker_value} "
            "found within the allotted window -- config was accepted but no data flowed",
        )
    assert delivered["namespace"] == namespace
    assert delivered["metric_name"] == metric_name

    cw.stop_metric_streams(Names=[stream_name])
    stopped = _poll_until(lambda: _get_stream(), lambda r: r["State"] == "stopped", timeout_s=30)
    assert stopped["State"] == "stopped"

    cw.delete_metric_stream(Name=stream_name)

    def _get_after_delete():
        # None while the stream still reads back; the poll times out loudly if it never stops.
        try:
            cw.get_metric_stream(Name=stream_name)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        return None

    code, message = _poll_until(_get_after_delete, lambda r: r is not None, timeout_s=20)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    # GetMetricStream answers not-found with an empty message.
    assert message == "", f"unexpected GetMetricStream message {message!r}"


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last={last!r}")


def _create_bucket(ctx, s3, bucket, resource_tags):
    # us-east-1 is a genuine S3 CreateBucket quirk: it rejects a LocationConstraint naming
    # the region it already defaults to.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": resource_tags})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)


def _create_role(ctx, iam, role_name, principal_service, inline_policy, resource_tags):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=resource_tags
    )
    arn = resp["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _create_delivery_stream(ctx, firehose, delivery_name, role_arn, bucket, resource_tags):
    deadline = time.monotonic() + 60
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = firehose.create_delivery_stream(
                DeliveryStreamName=delivery_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                },
                Tags=resource_tags,
            )
            break
        except ClientError as exc:
            last_err = exc
            code = exc.response["Error"]["Code"]
            if code in ("InvalidArgumentException", "ValidationException"):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"CreateDeliveryStream never succeeded: {last_err}")
    arn = resp["DeliveryStreamARN"]

    def _cleanup():
        try:
            firehose.delete_delivery_stream(DeliveryStreamName=delivery_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=delivery_name)
        status = desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return arn
        time.sleep(5)
    raise AssertionError("delivery stream never became ACTIVE")


def _delete_metric_stream_ignore(cw, name):
    # DeleteMetricStream has no ResourceNotFoundException in its model -- an unknown name is a
    # no-op, not a rejection -- so nothing here is expected to raise; let a real failure raise.
    cw.delete_metric_stream(Name=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
