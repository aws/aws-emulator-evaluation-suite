"""e2e-metric-stream-to-firehose-delivery-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-metric-stream-to-firehose-delivery-flow"
GROUP = "e2e"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real", "Value": "cloudwatch-metric-stream-to-firehose-delivery-flow"}]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A metric stream attached to a Firehose delivery stream moves published datapoints into the
    S3 destination: creating and starting the stream is not the same as data flowing."""
    namespace = ctx.unique_name("Sim2RealBehavStream")
    metric_name = "StreamedMetric"

    bucket = _create_bucket(ctx)
    firehose_role_arn = _create_role(
        ctx,
        "firehose.amazonaws.com",
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
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
    )
    delivery_stream_name = ctx.unique_name("sim2real-cwstream-fh-")
    delivery_stream_arn = _create_delivery_stream(ctx, delivery_stream_name, firehose_role_arn, bucket)

    metric_stream_role_arn = _create_role(
        ctx,
        "streams.metrics.cloudwatch.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": delivery_stream_arn,
                }
            ],
        },
    )

    cw = ctx.client("cloudwatch")
    stream_name = ctx.unique_name("sim2real-cwstream-")
    _retry_iam_propagation(
        lambda: cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=delivery_stream_arn,
            RoleArn=metric_stream_role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": namespace}],
            Tags=_TAGS,
        )
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))
    cw.start_metric_streams(Names=[stream_name])

    marker_value = 12345.0
    # 600 s: the first metric-stream object can take that long to reach S3 on AWS.
    left = ctx.time_left()
    deadline = time.monotonic() + (600.0 if left is None else min(600.0, left))
    while time.monotonic() < deadline:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": marker_value, "Unit": "Count"}],
        )
        time.sleep(5.0)
        if _find_record(ctx, bucket, namespace, metric_name, marker_value):
            return
    raise AssertionError(
        f"no Firehose-delivered record for {namespace}/{metric_name}={marker_value} found in "
        f"s3://{bucket} within the allotted window"
    )


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cwstream-bkt-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, principal: str, permissions_policy: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwstream-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="permissions", PolicyDocument=json.dumps(permissions_policy)
    )
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    iam.delete_role_policy(RoleName=role_name, PolicyName="permissions")
    iam.delete_role(RoleName=role_name)


def _create_delivery_stream(ctx, name: str, role_arn: str, bucket: str) -> str:
    firehose = ctx.client("firehose")
    # Firehose's own assume-role check lags IAM's trust-policy propagation, the same window
    # _retry_iam_propagation exists for below -- without a retry here CreateDeliveryStream
    # intermittently 400s with "Firehose is unable to assume role" on a role that is fine seconds
    # later.
    _retry_iam_propagation(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket}",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            },
            Tags=_TAGS,
        )
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        time.sleep(5.0)
    raise AssertionError(f"delivery stream {name} never became ACTIVE")


def _retry_iam_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - retrying on eventual IAM propagation
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _find_record(ctx, bucket: str, namespace: str, metric_name: str, value: float) -> bool:
    s3 = ctx.client("s3")
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
                if any(abs(v - value) < 1e-6 for v in values.values() if isinstance(v, (int, float))):
                    return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
