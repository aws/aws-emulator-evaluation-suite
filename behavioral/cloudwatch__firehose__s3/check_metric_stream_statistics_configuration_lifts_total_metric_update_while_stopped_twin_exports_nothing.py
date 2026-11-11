"""metric-stream-statistics-configuration-lifts-total-metric-update-while-stopped-twin-exports-nothing."""
from __future__ import annotations

import gzip
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metric-stream-statistics-configuration-lifts-total-metric-update-while-stopped-twin-exports-nothing"
GROUP = "metric-streams-delivery"
SERVICES = ["cloudwatch", "firehose", "s3"]

_VALUE = 777.0
_METRIC_NAME = "StreamedMetric"
_SHARDS = ("s0", "s1")
_PREFIX = "sim2real-obs2-stats/"
_TRUSTED = "streams.metrics.cloudwatch.amazonaws.com"
_MS_NAMESPACE = "AWS/CloudWatch/MetricStreams"
#: Six statistics beyond the default min/max/sum/count set.
_EXTRA_STATS = ["p10", "p50", "p90", "p99", "tm90", "wm90"]
_DEFAULT_VALUE_KEYS = {"count", "sum", "max", "min"}
_CEILING_S = 600.0
_POLL_S = 5.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-streams-monitoring.html
@tags(
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A StatisticsConfiguration lifts TotalMetricUpdate above MetricUpdate and adds the extra
    statistics to landed records; a twin stopped before any datapoint exports no record and reports
    no MetricUpdate while the control keeps exporting.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-streams-statistics.html
    """
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")

    bucket = _bucket(ctx)
    fh = _delivery_stream(ctx, bucket, _PREFIX, "stat")
    _await_active(ctx, [fh])
    namespace = ctx.unique_name("Sim2RealObs2StatsNs")
    role = _stream_role(ctx, [fh["arn"]], _TRUSTED, "stat")

    window_start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(
        minutes=1)
    stats = [{
        "IncludeMetrics": [{"Namespace": namespace, "MetricName": _METRIC_NAME}],
        "AdditionalStatistics": list(_EXTRA_STATS),
    }]
    subject = _metric_stream(ctx, namespace, fh["arn"], role, "sub", statistics=stats)
    control = _metric_stream(ctx, namespace, fh["arn"], role, "ctl")
    stopped = _metric_stream(ctx, namespace, fh["arn"], role, "stp")
    cw.stop_metric_streams(Names=[stopped])

    described = cw.get_metric_stream(Name=subject)
    assert described["State"] == "running", f"subject state: {described['State']!r}"
    got_stats = described.get("StatisticsConfigurations") or []
    assert len(got_stats) == 1 and sorted(got_stats[0]["AdditionalStatistics"]) == sorted(
        _EXTRA_STATS), f"StatisticsConfigurations read back as {got_stats!r}"
    assert got_stats[0]["IncludeMetrics"] == stats[0]["IncludeMetrics"], (
        f"StatisticsConfigurations IncludeMetrics read back as {got_stats[0]['IncludeMetrics']!r}")
    state = cw.get_metric_stream(Name=stopped)["State"]
    assert state == "stopped", f"twin {stopped!r} reads back {state!r} after StopMetricStreams"
    ctl_state = cw.get_metric_stream(Name=control)["State"]
    assert ctl_state == "running", f"control {control!r} is {ctl_state!r}; only the twin stopped"
    _publish(cw, namespace)

    dims = {name: [{"Name": "MetricStreamName", "Value": name}] for name in (subject, control, stopped)}

    def _observe():
        recs: dict = {subject: [], control: [], stopped: []}
        for rec in _records(s3, bucket, _list_objects(s3, bucket, _PREFIX)):
            if rec.get("namespace") == namespace and rec.get("metric_stream_name") in recs:
                recs[rec["metric_stream_name"]].append(rec)
        mu = _series(cw, "MetricUpdate", dims[subject], window_start)
        tot = _series(cw, "TotalMetricUpdate", dims[subject], window_start)
        return {
            "recs": recs,
            "pairs": {t: (mu[t], tot[t]) for t in mu if t in tot},
            "ctl mu": _series(cw, "MetricUpdate", dims[control], window_start),
            "stp mu": _series(cw, "MetricUpdate", dims[stopped], window_start),
        }

    def _ready(o):
        recs = o["recs"]
        return (
            any(set(r["value"]) - _DEFAULT_VALUE_KEYS for r in recs[subject])
            and recs[control]
            and o["ctl mu"]
            and any(t > m for m, t in o["pairs"].values())
        )

    seen = _poll(_observe, _ready,
                 republish=lambda: _publish(cw, namespace),
                 description="subject records with the additional statistics, TotalMetricUpdate > "
                             "MetricUpdate on the subject, and control records and MetricUpdate")
    lifted = {t: v for t, v in seen["pairs"].items() if v[1] > v[0]}
    assert lifted, f"no minute where TotalMetricUpdate exceeded MetricUpdate: {seen['pairs']!r}"
    # TotalMetricUpdate counts each additional statistic as an update; MetricUpdate counts the
    # metric once, so the lift is bounded by MetricUpdate * (1 + len(_EXTRA_STATS)).
    for t, (mu, tot) in lifted.items():
        assert tot <= mu * (1 + len(_EXTRA_STATS)), (
            f"at {t.isoformat()} TotalMetricUpdate {tot!r} exceeds MetricUpdate {mu!r} * "
            f"(1 + {len(_EXTRA_STATS)}) -- more statistics counted than were configured")

    extra = [set(r["value"]) - _DEFAULT_VALUE_KEYS for r in seen["recs"][subject]]
    widest = max(extra, key=len)
    assert len(widest) == len(_EXTRA_STATS), (
        f"a subject record carries {sorted(widest)!r} beyond the defaults, expected "
        f"{len(_EXTRA_STATS)} keys for {_EXTRA_STATS!r}")
    for rec in seen["recs"][control]:
        assert set(rec["value"]) == _DEFAULT_VALUE_KEYS, (
            f"the control stream's record carries {sorted(rec['value'])!r}; the subject's "
            f"StatisticsConfigurations leaked across streams: {rec!r}")

    # The control exporting the same namespace is the barrier before absence is asserted.
    assert seen["stp mu"] == {}, (
        f"twin {stopped!r}, stopped before any datapoint, reported MetricUpdate "
        f"{ {t.isoformat(): v for t, v in seen['stp mu'].items()}!r} while the control reported "
        f"{len(seen['ctl mu'])} minute(s)")
    assert seen["recs"][stopped] == [], (
        f"twin {stopped!r}, stopped before any datapoint, landed records for minutes "
        f"{sorted({r['timestamp'] for r in seen['recs'][stopped]})!r}")


def _series(cw, metric, dims, start) -> dict:
    """{minute: Sum} for one AWS/CloudWatch/MetricStreams metric."""
    pts = cw.get_metric_statistics(
        Namespace=_MS_NAMESPACE, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=["Sum"])["Datapoints"]
    return {p["Timestamp"]: float(p["Sum"]) for p in pts}


def _publish(cw, namespace):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": _METRIC_NAME, "Timestamp": now, "Value": _VALUE,
                     "Dimensions": [{"Name": "Shard", "Value": s}]} for s in _SHARDS],
    )
    return now


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
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
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


def _metric_stream(ctx, namespace, firehose_arn, role_arn, label, statistics=None) -> str:
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(f"sim2real-obs2-{label}-")
    # Registered BEFORE the call: PutMetricStream is an upsert with no synchronous validation.
    ctx.on_cleanup(lambda: _teardown(lambda: cw.delete_metric_stream(Name=name)))
    extra = {"StatisticsConfigurations": statistics} if statistics else {}
    _retry(lambda: cw.put_metric_stream(
        Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json",
        IncludeFilters=[{"Namespace": namespace}],
        Tags=[{"Key": "sim2real", "Value": "obs2"}],
        **extra,
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
