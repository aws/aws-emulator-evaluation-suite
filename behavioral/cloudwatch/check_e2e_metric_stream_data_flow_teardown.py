"""e2e-metric-stream-data-flow-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-metric-stream-data-flow-teardown"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Metric-Streams.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Metric stream over a live namespace runs, is confirmed RUNNING, actually delivers the
    published datapoint through Firehose into S3, is confirmed stopped, then fully torn down."""
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    namespace = ctx.unique_name("Sim2RealBehav/StreamE2E-")
    metric_name = "ThroughputBytes"
    stream_name = ctx.unique_name("sim2real-behav-mstream-")

    firehose_arn, _firehose_name, bucket = _create_firehose_to_s3(ctx)
    stream_role_arn = _create_metric_stream_role(ctx, firehose_arn)

    # feed a metric datum into the namespace the stream will be scoped to
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 42.0, "Unit": "Bytes"}],
    )

    stream_arn = _put_metric_stream_with_retry(
        ctx, stream_name=stream_name, namespace=namespace, firehose_arn=firehose_arn, role_arn=stream_role_arn
    )
    ctx.on_cleanup(lambda: _delete_stream_ignore(cw, stream_name))
    assert stream_arn

    cw.start_metric_streams(Names=[stream_name])

    def _probe_state() -> str:
        return cw.get_metric_stream(Name=stream_name)["State"]

    state = _poll_until(ctx, _probe_state, lambda s: s == "running", timeout_s=60.0, interval_s=2.0)
    assert state == "running"

    entries = cw.list_metric_streams()["Entries"]
    matching = [e for e in entries if e["Name"] == stream_name]
    assert len(matching) == 1 and matching[0]["State"] == "running"

    # A stream that reports "running" and answers every control-plane call is not the same as a
    # stream that actually moves data: confirm a fresh datapoint is delivered through Firehose into
    # the destination bucket, at the destination, before trusting the state field any further.
    marker_value = 4242.0
    record = _await_delivered_record(
        ctx, cw, s3, bucket=bucket, namespace=namespace, metric_name=metric_name, value=marker_value, timeout_s=600.0
    )
    assert record["namespace"] == namespace, record
    assert record["metric_name"] == metric_name, record
    delivered_values = record.get("value", {})
    assert any(
        isinstance(v, (int, float)) and abs(v - marker_value) < 1e-6 for v in delivered_values.values()
    ), f"delivered record carries value {delivered_values!r}, expected one entry == {marker_value!r}"

    cw.stop_metric_streams(Names=[stream_name])
    state = _poll_until(ctx, _probe_state, lambda s: s == "stopped", timeout_s=60.0, interval_s=2.0)
    assert state == "stopped"

    cw.delete_metric_stream(Name=stream_name)

    error = _error(lambda: cw.get_metric_stream(Name=stream_name))
    assert error == ("ResourceNotFoundException", ""), error


def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline of `seconds`, capped by the run's remaining budget."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = _deadline(ctx, timeout_s)
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never became true within {timeout_s}s; last={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _await_delivered_record(ctx, cw, s3, *, bucket: str, namespace: str, metric_name: str, value: float, timeout_s: float):
    """Republish the marker datum and poll the destination bucket until Firehose delivers it.

    A metric stream exports only what is actively arriving, so a single publish can land in a
    buffering window with nothing in it -- republish every cycle rather than seeding once and
    waiting.
    """
    deadline = _deadline(ctx, timeout_s)
    while True:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": value, "Unit": "Bytes"}],
        )
        record = _find_delivered_record(s3, bucket, namespace, metric_name)
        if record is not None:
            return record
        if time.monotonic() > deadline:
            raise AssertionError(
                f"metric stream never delivered a record for {namespace}/{metric_name} to "
                f"s3://{bucket} within {timeout_s}s"
            )
        time.sleep(2.0)


def _find_delivered_record(s3, bucket: str, namespace: str, metric_name: str) -> dict | None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("namespace") == namespace and record.get("metric_name") == metric_name:
                    return record
    return None


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_stream_ignore(cw, name: str) -> None:
    try:
        cw.delete_metric_stream(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_firehose_to_s3(ctx) -> tuple[str, str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-behav-mstreambkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # CreateBucket rejects a LocationConstraint that names the region it is already defaulting
        # to, so us-east-1 is the one region that must omit it -- an S3 API quirk, not a region pin.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "cloudwatch-metric-stream-teardown"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-behav-fhrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch-metric-stream-teardown"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket", "s3:AbortMultipartUpload", "s3:PutObjectAcl"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _delete_role_policy_ignore(iam, role_name, "s3-access"))

    fh_name = ctx.unique_name("sim2real-behav-fh-")
    # IAM role propagation lag: retry create_delivery_stream for a bit.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=fh_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    # Zero buffering: the claim is that data flows, not how long Firehose holds it.
                    "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
                },
                Tags=[{"Key": "sim2real", "Value": "cloudwatch-metric-stream-teardown"}],
            )
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _delete_delivery_stream_ignore(firehose, fh_name))

    def _probe_active() -> str:
        return firehose.describe_delivery_stream(DeliveryStreamName=fh_name)["DeliveryStreamDescription"]["DeliveryStreamStatus"]

    status = _poll_until(ctx, _probe_active, lambda s: s == "ACTIVE", timeout_s=120.0, interval_s=2.0)
    assert status == "ACTIVE"

    fh_arn = firehose.describe_delivery_stream(DeliveryStreamName=fh_name)["DeliveryStreamDescription"]["DeliveryStreamARN"]
    return fh_arn, fh_name, bucket


def _create_metric_stream_role(ctx, firehose_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-msrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch-metric-stream-teardown"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore(iam, role_name))
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
    ctx.on_cleanup(lambda: _delete_role_policy_ignore(iam, role_name, "firehose-access"))
    return role_arn


def _put_metric_stream_with_retry(ctx, *, stream_name: str, namespace: str, firehose_arn: str, role_arn: str) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = cw.put_metric_stream(
                Name=stream_name,
                IncludeFilters=[{"Namespace": namespace}],
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
            )
            return resp["Arn"]
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_role_policy_ignore(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_ignore(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_delivery_stream_ignore(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
