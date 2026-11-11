"""metric-stream-delivers-one-metrics-minutes-in-timestamp-order."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metric-stream-delivers-one-metrics-minutes-in-timestamp-order"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Metric-Streams.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A metric stream exports one metric's minutes in timestamp order: datapoints carrying an
    explicit timestamp and one value per minute land in the Firehose S3 output as one record per
    minute, in minute order, each carrying exactly that minute's value.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-streams-troubleshoot.html
    """
    cw = ctx.client("cloudwatch")
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    firehose_arn = _create_firehose_stream(ctx, role_arn, bucket)
    ms_role_arn = _create_metric_stream_role(ctx, firehose_arn)

    ns = ctx.unique_name("sim2real-cw-order-ns-")
    metric_name = "OrderedDeliveryMetric"
    dims = [{"Name": "Case", "Value": "ordered"}]
    stream_name = ctx.unique_name("sim2real-cw-order-stream-")
    _retry_until_ready(
        lambda: cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=ms_role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": ns}],
            Tags=[{"Key": "sim2real-owner", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))
    cw.start_metric_streams(Names=[stream_name])

    described = cw.get_metric_stream(Name=stream_name)
    assert described["State"] == "running", f"metric stream {stream_name!r} is {described['State']!r}, expected 'running'"

    # Each minute carries ONE value, published every few seconds with an explicit timestamp in
    # that same minute, so every delivered minute record is min == max == that minute's value
    # however many of its datapoints a just-started stream drops. A metric stream exports a
    # minute once; a datapoint sent later for that minute is not exported again.
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    base_ms = int(base.timestamp() * 1000)

    def value_for(minute_ms: int) -> float:
        return 100.0 * ((minute_ms - base_ms) // 60_000 + 1)

    def publish() -> None:
        now = datetime.now(timezone.utc)
        minute_ms = int(now.replace(second=0, microsecond=0).timestamp() * 1000)
        cw.put_metric_data(Namespace=ns, MetricData=[{
            "MetricName": metric_name, "Dimensions": dims, "Timestamp": now,
            "Value": value_for(minute_ms), "Unit": "Count",
        }])

    left = ctx.time_left()
    timeout_s = 420.0 if left is None else max(1.0, min(420.0, left - 30.0))
    records = _poll_s3_for_all_metric_records(ctx, bucket, ns, metric_name, expected_count=3,
                                              timeout_s=timeout_s, on_iteration=publish)
    assert records is not None, (
        f"expected 3 delivered minute records for the metric, never observed within {timeout_s}s"
    )

    # Key order approximates delivery order, which is the ordering under test.
    timestamps = [r["timestamp"] for r in records]
    assert timestamps == sorted(timestamps), (
        f"delivered minute records are not in timestamp order: {timestamps}"
    )
    assert all(t % 60_000 == 0 and t >= base_ms for t in timestamps), (
        f"delivered timestamps {timestamps} are not minutes at or after the first publish {base_ms}"
    )
    for rec in records:
        want = value_for(rec["timestamp"])
        value = rec["value"]
        assert value["min"] == value["max"] == want, (
            f"the minute {rec['timestamp']} carries {value!r}; every datapoint in it is {want}"
        )
        assert value["count"] >= 1 and value["sum"] == value["count"] * want, (
            f"the minute {rec['timestamp']} sum must be count * {want}, got {value!r}"
        )


def _retry_until_ready(fn, timeout_s=90.0, interval_s=5.0):
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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real-owner", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real-owner", "Value": CHECK}],
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
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "sim2real-owner", "Value": CHECK}],
        )

    _retry_until_ready(_create, timeout_s=90)
    ctx.on_cleanup(lambda: _delete_delivery_stream(fh, name))

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


def _delete_delivery_stream(fh, name, timeout_s=300.0):
    """Delete the delivery stream and wait until it is gone; only not-found means gone."""
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name)
    except fh.exceptions.ResourceNotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = fh.describe_delivery_stream(
                DeliveryStreamName=name)["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        except fh.exceptions.ResourceNotFoundException:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name!r} still {status!r} {timeout_s}s after delete")
        time.sleep(5)


def _poll_s3_for_all_metric_records(ctx, bucket, namespace, metric_name, expected_count, timeout_s, on_iteration, interval_s=5.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        on_iteration()
        records = []
        seen_timestamps = set()
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            # Key order approximates delivery order, which is the ordering under test.
            for obj in sorted(page.get("Contents", []), key=lambda o: o["Key"]):
                body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                for line in body.splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("namespace") == namespace and rec.get("metric_name") == metric_name:
                        # Firehose is at-least-once; keep the first arrival per timestamp.
                        if rec["timestamp"] in seen_timestamps:
                            continue
                        seen_timestamps.add(rec["timestamp"])
                        records.append(rec)
        if len(records) >= expected_count:
            return records[:expected_count]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
