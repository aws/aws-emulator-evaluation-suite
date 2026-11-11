"""deep-cloudwatch-3-cwstreamfmt-otel-rejects-average-additional-statistic."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-cloudwatch-3-cwstreamfmt-otel-rejects-average-additional-statistic"
GROUP = "metric-streams-validation"
SERVICES = ["cloudwatch", "firehose", "s3"]

_OTEL = "opentelemetry1.0"
_TRIMMED = "TM(10%:90%)"


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "plane:control",
)
def run(ctx) -> None:
    """Metric-stream AdditionalStatistics is checked against OutputFormat: Average is refused for
    every format, a trimmed mean only for OTel; refused creates and upserts leave state unchanged.
    """
    cw = ctx.client("cloudwatch")
    bucket = _bucket(ctx)
    fh_arn = _delivery_stream(ctx, bucket)
    role_arn = _role(ctx, "ms", "streams.metrics.cloudwatch.amazonaws.com", {
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
            "Resource": [fh_arn]}]})
    namespace = ctx.unique_name("Sim2RealCwStreamFmt")
    name = ctx.unique_name("sim2real-cwstreamfmt-")
    ctx.on_cleanup(_teardown(lambda: cw.delete_metric_stream(Name=name)))

    def _put(fmt, stats):
        return cw.put_metric_stream(
            Name=name, FirehoseArn=fh_arn, RoleArn=role_arn, OutputFormat=fmt,
            IncludeFilters=[{"Namespace": namespace}],
            StatisticsConfigurations=[{
                "IncludeMetrics": [{"Namespace": namespace, "MetricName": "Latency"}],
                "AdditionalStatistics": stats,
            }],
        )

    # 1. Refused creates leave no stream behind. Average is not an "additional" statistic at all,
    # so even json refuses it.
    for fmt, stat in ((_OTEL, "Average"), ("json", "Average"), (_OTEL, _TRIMMED)):
        got_err = _error(lambda f=fmt, s=stat: _put(f, [s]))
        expected = ("InvalidParameterValue", _unsupported(stat))
        assert got_err == expected, (
            f"OutputFormat={fmt!r} AdditionalStatistics=[{stat!r}] failed with {got_err!r}, "
            f"expected {expected!r}"
        )
        missing = _error(lambda: cw.get_metric_stream(Name=name))
        expected_missing = ("ResourceNotFoundException", "")  # AWS sends this one with no message
        assert missing == expected_missing, (
            f"after the refused {fmt!r}/{stat!r} create, GetMetricStream returned {missing!r}, "
            f"expected {expected_missing!r}; the stream must not exist"
        )

    # 2. Positive control: OTel + a percentile is accepted, and reads back as configured.
    _retry(ctx, lambda: _put(_OTEL, ["p99"]))
    got = cw.get_metric_stream(Name=name)
    assert got["OutputFormat"] == _OTEL, f"{got['OutputFormat']!r}"
    assert got["StatisticsConfigurations"][0]["AdditionalStatistics"] == ["p99"], (
        f"{got['StatisticsConfigurations']!r}"
    )

    # 3. The trimmed mean OTel refused is accepted for json: the rule is format-dependent.
    _put("json", [_TRIMMED])
    got = cw.get_metric_stream(Name=name)
    assert got["OutputFormat"] == "json", f"{got['OutputFormat']!r}"
    assert got["StatisticsConfigurations"][0]["AdditionalStatistics"] == [_TRIMMED], (
        f"json + {_TRIMMED!r} was accepted but reads back {got['StatisticsConfigurations']!r}"
    )

    # 4. A refused UPSERT of the existing stream must leave it exactly as it was.
    got_err = _error(lambda: _put(_OTEL, [_TRIMMED]))
    expected = ("InvalidParameterValue", _unsupported(_TRIMMED))
    assert got_err == expected, (
        f"upserting the json stream to {_OTEL!r} with [{_TRIMMED!r}] failed with {got_err!r}, "
        f"expected {expected!r}"
    )
    after = cw.get_metric_stream(Name=name)
    assert after["OutputFormat"] == "json", (
        f"a REFUSED upsert changed the stream's OutputFormat to {after['OutputFormat']!r}"
    )
    assert after["StatisticsConfigurations"] == got["StatisticsConfigurations"], (
        f"a REFUSED upsert changed StatisticsConfigurations from "
        f"{got['StatisticsConfigurations']!r} to {after['StatisticsConfigurations']!r}"
    )


def _unsupported(stat):
    return f"Unsupported statistic {stat} for selected OutputFormat"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected SUCCESS is itself a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"call was expected to be refused but succeeded: {resp!r}")


def _bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cwstreamfmt-")
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        stale = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if stale:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": stale}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _role(ctx, label, trust_service, policy_doc):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-cwstreamfmt-{label}-")
    arn = iam.create_role(
        RoleName=name,
        Description="sim2real cwstreamfmt metric stream validation",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": "cwstreamfmt"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _delivery_stream(ctx, bucket):
    firehose = ctx.client("firehose")
    role_arn = _role(ctx, "fh", "firehose.amazonaws.com", {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                   "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}]})
    # IAM exposes no propagation condition: _retry repeats the first use of the role to a deadline.
    name = ctx.unique_name("sim2real-cwstreamfmt-")
    _retry(ctx, lambda: firehose.create_delivery_stream(
        DeliveryStreamName=name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=[{"Key": "sim2real", "Value": "cwstreamfmt"}],
    ))
    ctx.on_cleanup(_teardown(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
        "ResourceNotFoundException"))
    deadline = _deadline(ctx, 300.0)
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name!r} stalled in {desc['DeliveryStreamStatus']!r}")
        time.sleep(2.0)


def _deadline(ctx, seconds):
    """A monotonic deadline of `seconds`, capped by the run's remaining budget."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _retry(ctx, fn, budget_s=60.0, interval_s=2.0):
    """Retry, to a deadline, over the IAM-propagation window at first use of a new role."""
    deadline = _deadline(ctx, budget_s)
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") in (
                "AccessDenied", "AccessDeniedException", "InvalidArgumentException",
                "ValidationException",
            ) and any(w in msg for w in ("assume", "not authorized", "role", "iam"))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _teardown(undo, *not_found: str):
    """A cleanup running `undo()` where a failed delete raises; only its own not-found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
