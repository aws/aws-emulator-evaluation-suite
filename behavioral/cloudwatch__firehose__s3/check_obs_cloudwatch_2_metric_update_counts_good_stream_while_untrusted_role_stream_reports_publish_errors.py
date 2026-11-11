"""obs-cloudwatch-2-metric-update-counts-good-stream-while-untrusted-role-stream-reports-publish-errors."""
from __future__ import annotations

import gzip
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = (
    "obs-cloudwatch-2-metric-update-counts-good-stream-while-untrusted-role-stream-reports-publish-errors"
)
GROUP = "metric-streams-delivery"
SERVICES = ["cloudwatch", "firehose", "s3"]

_VALUE = 777.0
_METRIC_NAME = "StreamedMetric"
#: One series per Shard value: the published series count the MetricUpdate sums are held to.
_SHARDS = ("s0", "s1", "s2")
_SERIES = len(_SHARDS)
_GOOD_PREFIX = "sim2real-obs2-good/"
_BROKEN_PREFIX = "sim2real-obs2-broken/"
_TRUSTED = "streams.metrics.cloudwatch.amazonaws.com"
_UNTRUSTED = "ec2.amazonaws.com"
_MS_NAMESPACE = "AWS/CloudWatch/MetricStreams"
#: Every eventually-consistent wait in this file is bounded by this ceiling.
_CEILING_S = 600.0
_POLL_S = 20.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-streams-monitoring.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Two metric streams on one namespace differ only in the role's trusted principal.

    The trusted stream's MetricUpdate reaches the published series count and its PublishErrorRate
    is exactly 0.0; the untrusted stream reports PublishErrorRate > 0 and delivers nothing to S3.
    """
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")

    bucket = _bucket(ctx)
    good_fh = _delivery_stream(ctx, bucket, _GOOD_PREFIX, "good")
    broken_fh = _delivery_stream(ctx, bucket, _BROKEN_PREFIX, "brkn")
    _await_active(ctx, [good_fh, broken_fh])

    namespace = ctx.unique_name("Sim2RealObs2Ns")
    fh_arns = [good_fh["arn"], broken_fh["arn"]]
    good_role = _stream_role(ctx, fh_arns, _TRUSTED, "good")
    broken_role = _stream_role(ctx, fh_arns, _UNTRUSTED, "brkn")

    window_start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(
        minutes=1)
    good_stream = _metric_stream(ctx, namespace, good_fh["arn"], good_role, "gms")
    broken_stream = _metric_stream(ctx, namespace, broken_fh["arn"], broken_role, "bms")
    for name in (good_stream, broken_stream):
        state = cw.get_metric_stream(Name=name)["State"]
        assert state == "running", f"metric stream {name!r} is {state!r}, expected 'running'"

    _publish(cw, namespace)

    # Barrier: the trusted stream must have delivered, and more than once.
    good_keys = _poll_objects(
        s3, bucket, _GOOD_PREFIX, predicate=lambda keys: len(keys) >= 2,
        republish=lambda: _publish(cw, namespace),
        description=f"the trusted stream exported >= 2 objects to s3://{bucket}/{_GOOD_PREFIX}",
    )
    mine = [r for r in _records(s3, bucket, good_keys) if r.get("namespace") == namespace]
    assert mine, f"no delivered record in {good_keys!r} carries namespace {namespace!r}"
    shards = {(r.get("dimensions") or {}).get("Shard") for r in mine}
    assert shards == set(_SHARDS), (
        f"delivered records carry Shard dimensions {sorted(map(str, shards))!r}, expected "
        f"exactly {sorted(_SHARDS)!r}")
    for rec in mine:
        assert rec["metric_name"] == _METRIC_NAME, f"{rec!r}"
        assert set(rec["dimensions"]) == {"Shard"}, f"dimensions are {rec['dimensions']!r}"
        value = rec["value"]
        assert "sum" in value and "count" in value, f"value lacks sum/count: {value!r}"
        assert value["count"] >= 1, f"value.count is {value['count']!r}: {rec!r}"
        assert value["sum"] == value["count"] * _VALUE, (
            f"value.sum {value['sum']!r} != value.count {value['count']!r} * {_VALUE!r}: {rec!r}")
        assert rec["metric_stream_name"] == good_stream, f"{rec!r}"

    good_dims = [{"Name": "MetricStreamName", "Value": good_stream}]
    broken_dims = [{"Name": "MetricStreamName", "Value": broken_stream}]

    def _observe():
        return {
            "good MetricUpdate": _dps(cw, "MetricUpdate", good_dims, window_start, "Sum"),
            "all MetricUpdate": _dps(cw, "MetricUpdate", [], window_start, "Sum"),
            "broken PublishErrorRate": _dps(cw, "PublishErrorRate", broken_dims, window_start,
                                            "Average"),
            "good PublishErrorRate": _dps(cw, "PublishErrorRate", good_dims, window_start,
                                          "Average"),
        }

    def _ready(o):
        return (max(o["good MetricUpdate"], default=0.0) >= _SERIES
                and max(o["all MetricUpdate"], default=0.0) >= _SERIES
                and max(o["broken PublishErrorRate"], default=0.0) > 0
                and o["good PublishErrorRate"])

    seen = _poll(_observe, _ready, republish=lambda: _publish(cw, namespace),
                 description="MetricUpdate >= series count (filtered and aggregate) and "
                             "untrusted PublishErrorRate > 0")
    assert max(seen["good MetricUpdate"]) >= _SERIES, (
        f"MetricUpdate[MetricStreamName={good_stream}] per-minute sums {seen['good MetricUpdate']!r}"
        f" never reached the {_SERIES} published series")
    assert max(seen["all MetricUpdate"]) >= max(seen["good MetricUpdate"]), (
        f"the no-dimension MetricUpdate aggregate {seen['all MetricUpdate']!r} is smaller than "
        f"one stream's own count {seen['good MetricUpdate']!r}")
    rates = seen["broken PublishErrorRate"]
    assert all(0.0 <= r <= 1.0 for r in rates), f"PublishErrorRate outside [0,1]: {rates!r}"
    assert max(rates) > 0, f"untrusted stream PublishErrorRate never exceeded 0: {rates!r}"

    # Isolation, over the SAME window: the trusted stream publishes PublishErrorRate too, and every
    # one of its datapoints is exactly 0 -- the untrusted stream's errors do not leak into it.
    good_rates = seen["good PublishErrorRate"]
    assert good_rates and all(r == 0.0 for r in good_rates), (
        f"the trusted stream {good_stream!r} reported PublishErrorRate datapoints {good_rates!r} "
        f"while the untrusted stream reported {rates!r}; expected only 0.0 datapoints")

    # Effect absent at the destination, past the barrier.
    broken_keys = _list_objects(s3, bucket, _BROKEN_PREFIX)
    assert broken_keys == [], (
        f"the stream whose role trusts {_UNTRUSTED!r} still exported {broken_keys!r}")


# ===== helpers =====
def _publish(cw, namespace):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": _METRIC_NAME, "Timestamp": now, "Value": _VALUE,
                     "Dimensions": [{"Name": "Shard", "Value": s}]} for s in _SHARDS],
    )
    return now


def _dps(cw, metric, dims, start, stat) -> list[float]:
    """Per-minute values of one AWS/CloudWatch/MetricStreams metric, oldest first."""
    pts = cw.get_metric_statistics(
        Namespace=_MS_NAMESPACE, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=[stat])["Datapoints"]
    return [float(p[stat]) for p in sorted(pts, key=lambda p: p["Timestamp"])]


def _poll(observe, ready, *, republish, description):
    deadline = time.monotonic() + _CEILING_S
    while True:
        seen = observe()
        if ready(seen):
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not reached within {_CEILING_S}s; last {seen!r}")
        republish()
        time.sleep(_POLL_S)


def _bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-obs2-")
    kw: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "obs2"}]})
    return name


def _empty_and_delete_bucket(s3, bucket) -> None:
    """Firehose deletion is asynchronous and can flush one last object after the bucket was
    emptied, so empty-then-delete is retried over a bounded window."""
    deadline = time.monotonic() + 120.0
    while True:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            stale = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if stale:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": stale}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() > deadline:
                raise RuntimeError(f"s3 bucket {bucket}: {exc}") from exc
            time.sleep(5.0)


def _role(ctx, label, trust_service, policy_doc) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-obs2-{label}-")
    arn = iam.create_role(
        RoleName=name,
        Description="sim2real obs-cloudwatch-2 metric stream export",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": "obs2"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=name)))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-obs2",
                        PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-obs2")))
    return arn


def _stream_role(ctx, firehose_arns, trusted_service, label) -> str:
    return _role(ctx, f"ms{label}", trusted_service, {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                       "Resource": list(firehose_arns)}],
    })


def _delivery_stream(ctx, bucket, prefix, label) -> dict:
    firehose = ctx.client("firehose")
    role_arn = _role(ctx, f"fh{label}", "firehose.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation",
                                  "s3:GetObject", "s3:ListBucket",
                                  "s3:ListBucketMultipartUploads", "s3:PutObject"],
                       "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}],
    })
    name = ctx.unique_name(f"sim2real-obs2-fh{label}-")
    _retry(lambda: firehose.create_delivery_stream(
        DeliveryStreamName=name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": prefix,
            "ErrorOutputPrefix": f"{prefix}errors/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=[{"Key": "sim2real", "Value": "obs2"}],
    ))
    ctx.on_cleanup(lambda: _teardown(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name)))
    arn = firehose.describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"]["DeliveryStreamARN"]
    return {"name": name, "arn": arn}


def _await_active(ctx, streams) -> None:
    firehose = ctx.client("firehose")

    def _one(stream):
        deadline = time.monotonic() + 300.0
        while True:
            status = firehose.describe_delivery_stream(DeliveryStreamName=stream["name"])[
                "DeliveryStreamDescription"]["DeliveryStreamStatus"]
            if status == "ACTIVE":
                return status
            if time.monotonic() >= deadline:
                raise AssertionError(f"delivery stream {stream['name']!r} stalled in {status!r}")
            time.sleep(5.0)

    with ThreadPoolExecutor(max_workers=len(streams)) as pool:
        for status in pool.map(_one, streams):
            assert status == "ACTIVE", f"{status!r}"


def _metric_stream(ctx, namespace, firehose_arn, role_arn, label) -> str:
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(f"sim2real-obs2-{label}-")
    # Registered BEFORE the call: PutMetricStream is an upsert with no synchronous validation.
    ctx.on_cleanup(lambda: _teardown(lambda: cw.delete_metric_stream(Name=name)))
    _retry(lambda: cw.put_metric_stream(
        Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json",
        IncludeFilters=[{"Namespace": namespace}],
        Tags=[{"Key": "sim2real", "Value": "obs2"}],
    ))
    return name


def _list_objects(s3, bucket, prefix) -> list[str]:
    """Every key under prefix, paginated, excluding Firehose's own <prefix>errors/ output."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if not obj["Key"].startswith(f"{prefix}errors/"):
                keys.append(obj["Key"])
    return sorted(keys)


def _poll_objects(s3, bucket, prefix, *, predicate, republish, description):
    deadline = time.monotonic() + _CEILING_S
    while True:
        keys = _list_objects(s3, bucket, prefix)
        if predicate(keys):
            return keys
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not within {_CEILING_S}s; last {keys!r}")
        republish()
        time.sleep(_POLL_S)


def _records(s3, bucket, keys) -> list[dict]:
    out = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        out.extend(_split_json(body.decode("utf-8")))
    return out


def _split_json(blob) -> list[dict]:
    """Concatenated JSON documents, newline-separated or not."""
    decoder = json.JSONDecoder()
    out, idx = [], 0
    while idx < len(blob):
        while idx < len(blob) and blob[idx] in " \r\n\t":
            idx += 1
        if idx >= len(blob):
            break
        obj, idx = decoder.raw_decode(blob, idx)
        out.append(obj)
    return out


def _retry(fn, attempts=12, interval_s=5.0):
    """Bounded IAM-propagation retry at first use of a freshly created role."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") in (
                "AccessDenied", "AccessDeniedException", "ValidationException",
                "InvalidArgumentException",
            ) and any(w in msg for w in ("assume", "not authorized", "trust", "iam", "role"))
            if not transient or i == attempts - 1:
                raise
            time.sleep(interval_s)
    raise AssertionError("unreachable")


def _teardown(fn) -> None:
    """Run one teardown call: return when the resource is already gone, retry while it is still in use."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NoSuchEntity", "ResourceNotFoundException", "ResourceNotFound"):
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
