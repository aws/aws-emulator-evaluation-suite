"""deep-cloudwatch-3-cwstreamfmt-otel-delivers-length-delimited-protobuf-with-p99."""
from __future__ import annotations

import json
import struct
import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-cloudwatch-3-cwstreamfmt-otel-delivers-length-delimited-protobuf-with-p99"
GROUP = "metric-streams-delivery"
SERVICES = ["cloudwatch", "firehose", "s3"]

_PREFIX = "sim2real-otel/"
_P99_METRIC = "Latency"        # named in StatisticsConfigurations -> streams p99
_CONTROL_METRIC = "Throughput"  # same namespace, NOT named -> base statistics only
# 1..100, each once, per publish: min 1, max 100, sum 5050, count 100 per publish.
_VALUES = [float(v) for v in range(1, 101)]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """An opentelemetry1.0 metric stream lands length-delimited OTLP protobuf (not JSON) in S3 with the
    expected resource attributes and Summary values, and only the metric named in
    StatisticsConfigurations carries the p99 quantile.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-streams-formats-opentelemetry-100.html
    """
    iam_propagation_s = 10.0
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    namespace = ctx.unique_name("Sim2RealCwStreamFmt")

    bucket = _bucket(ctx)
    fh_name, fh_arn = _delivery_stream(ctx, bucket, iam_propagation_s)
    stream_role = _role(
        ctx, "ms", "streams.metrics.cloudwatch.amazonaws.com",
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
            "Resource": [fh_arn]}]},
    )
    _await_active(ctx.client("firehose"), fh_name)

    stream = ctx.unique_name("sim2real-cwstreamfmt-")
    # Registered BEFORE the call: PutMetricStream is an upsert, so the stream can exist even if a
    # later assertion fails.
    ctx.on_cleanup(lambda: _teardown(lambda: cw.delete_metric_stream(Name=stream)))
    stream_arn = _retry(lambda: cw.put_metric_stream(
        Name=stream,
        FirehoseArn=fh_arn,
        RoleArn=stream_role,
        OutputFormat="opentelemetry1.0",
        IncludeFilters=[{"Namespace": namespace}],
        StatisticsConfigurations=[{
            "IncludeMetrics": [{"Namespace": namespace, "MetricName": _P99_METRIC}],
            "AdditionalStatistics": ["p99"],
        }],
        Tags=[{"Key": "sim2real", "Value": "cwstreamfmt"}],
    ))["Arn"]
    described = cw.get_metric_stream(Name=stream)
    assert described["State"] == "running", f"metric stream state {described['State']!r}"
    assert described["OutputFormat"] == "opentelemetry1.0", f"{described['OutputFormat']!r}"

    def _publish():
        now = datetime.now(timezone.utc)
        cw.put_metric_data(Namespace=namespace, MetricData=[
            {"MetricName": m, "Values": _VALUES, "Counts": [1.0] * len(_VALUES), "Timestamp": now}
            for m in (_P99_METRIC, _CONTROL_METRIC)
        ])

    # The first object lands roughly 240 s after the stream starts (Firehose buffering).
    deadline = time.monotonic() + 780.0
    bodies, summaries = {}, {}
    while True:
        _publish()
        for key in _list_objects(s3, bucket):
            if key not in bodies:
                bodies[key] = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                for req in _split_delimited(bodies[key], key):
                    for found in _summaries(req):
                        if found["datapoint_attrs"].get("Namespace") == namespace:
                            summaries.setdefault(found["datapoint_attrs"].get("MetricName"), []).append(found)
        if _P99_METRIC in summaries and _CONTROL_METRIC in summaries:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the OTel stream did not deliver both {_P99_METRIC!r} and {_CONTROL_METRIC!r} "
                f"for namespace {namespace!r} to s3://{bucket}/{_PREFIX} within 780s; objects "
                f"{sorted(bodies)!r}, metrics decoded {sorted(summaries)!r}"
            )
        time.sleep(15.0)

    for key, body in bodies.items():
        assert not body.lstrip().startswith(b"{"), (
            f"{key} starts like JSON ({body[:60]!r}); an opentelemetry1.0 stream must not deliver "
            f"the json line format"
        )
        assert not _parses_as_json_lines(body), (
            f"{key} parses as newline-delimited JSON; opentelemetry1.0 must deliver protobuf"
        )

    for name, found_list in summaries.items():
        for found in found_list:
            res = found["resource_attrs"]
            assert res.get("cloud.provider") == "aws", f"{name}: resource {res!r}"
            assert res.get("cloud.account.id") == account_id, f"{name}: resource {res!r}"
            assert res.get("cloud.region") == ctx.region, f"{name}: resource {res!r}"
            assert res.get("aws.exporter.arn") == stream_arn, (
                f"{name}: aws.exporter.arn is {res.get('aws.exporter.arn')!r}, expected {stream_arn!r}"
            )
            assert found["name"] == f"amazonaws.com/{namespace}/{name}", f"{found['name']!r}"
            assert found["unit"] == "1", f"{name}: unit {found['unit']!r}, expected '1'"
            q = found["quantiles"]
            assert q.get(0.0) == 1.0 and q.get(1.0) == 100.0, (
                f"{name}: quantiles {q!r}; min (0.0) must be 1 and max (1.0) must be 100"
            )
            count = found["count"]
            assert count > 0 and count % len(_VALUES) == 0, f"{name}: count {count!r}"
            assert found["sum"] == 50.5 * count, (
                f"{name}: sum {found['sum']!r} for count {count!r}, expected {50.5 * count!r}"
            )

    for found in summaries[_P99_METRIC]:
        q = found["quantiles"]
        assert 0.99 in q, (
            f"{_P99_METRIC} was configured with AdditionalStatistics=['p99'] but its delivered "
            f"summary carries quantiles {sorted(q)!r} -- no 0.99"
        )
        # CloudWatch percentiles are approximations (p99 of 1..100 reports ~98.9), hence the range.
        assert 95.0 <= q[0.99] <= 100.0, f"p99 of 1..100 delivered as {q[0.99]!r}"
    for found in summaries[_CONTROL_METRIC]:
        assert sorted(found["quantiles"]) == [0.0, 1.0], (
            f"{_CONTROL_METRIC} is not named in StatisticsConfigurations yet its summary carries "
            f"quantiles {sorted(found['quantiles'])!r}; only min/max (0.0, 1.0) are base statistics"
        )


# --- minimal protobuf wire-format reader (stdlib only) ---
def _varint(buf, i):
    shift = result = 0
    while True:
        if i >= len(buf):
            raise AssertionError(f"truncated varint at offset {i}")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _fields(buf):
    """[(field_number, wire_type, value)] -- value is int, bytes (len-delimited) or 8/4 raw bytes."""
    out, i = [], 0
    while i < len(buf):
        tag, i = _varint(buf, i)
        field, wt = tag >> 3, tag & 7
        if wt == 0:
            val, i = _varint(buf, i)
        elif wt == 1:
            val, i = buf[i:i + 8], i + 8
        elif wt == 2:
            n, i = _varint(buf, i)
            val, i = buf[i:i + n], i + n
        elif wt == 5:
            val, i = buf[i:i + 4], i + 4
        else:
            raise AssertionError(f"unsupported protobuf wire type {wt} at offset {i}")
        if i > len(buf):
            raise AssertionError("protobuf field overruns its buffer")
        out.append((field, wt, val))
    return out


def _split_delimited(body, key):
    """Varint-length-delimited messages that must tile body exactly."""
    msgs, i = [], 0
    while i < len(body):
        n, j = _varint(body, i)
        assert n > 0 and j + n <= len(body), (
            f"{key}: length prefix {n} at offset {i} overruns the {len(body)}-byte object -- not "
            f"length-delimited protobuf"
        )
        msgs.append(body[j:j + n])
        i = j + n
    assert msgs, f"{key} is empty"
    return msgs


def _double(raw):
    return struct.unpack("<d", raw)[0]


def _kv(raw):
    key, value = None, None
    for f, _, v in _fields(raw):
        if f == 1:
            key = v.decode()
        elif f == 2:
            for af, _, av in _fields(v):
                if af == 1:
                    value = av.decode()
    return key, value


def _summaries(req):
    """Every Summary datapoint in one ExportMetricsServiceRequest."""
    out = []
    for f, _, rm in _fields(req):
        if f != 1:
            continue
        resource_attrs, scope_metrics = {}, []
        for rf, _, rv in _fields(rm):
            if rf == 1:
                resource_attrs = dict(_kv(a) for af, _, a in _fields(rv) if af == 1)
            elif rf == 2:
                scope_metrics.append(rv)
        for sm in scope_metrics:
            for sf, _, metric in _fields(sm):
                if sf != 2:
                    continue
                name = unit = None
                summary = None
                for mf, _, mv in _fields(metric):
                    if mf == 1:
                        name = mv.decode()
                    elif mf == 3:
                        unit = mv.decode()
                    elif mf == 11:
                        summary = mv
                if summary is None:
                    continue
                for pf, _, dp in _fields(summary):
                    if pf != 1:
                        continue
                    point = {"name": name, "unit": unit, "resource_attrs": resource_attrs,
                             "datapoint_attrs": {}, "quantiles": {}, "count": 0, "sum": 0.0}
                    for df, _, dv in _fields(dp):
                        if df == 7:
                            k, v = _kv(dv)
                            point["datapoint_attrs"][k] = v
                        elif df == 4:
                            point["count"] = struct.unpack("<Q", dv)[0]
                        elif df == 5:
                            point["sum"] = _double(dv)
                        elif df == 6:
                            qv = {qf: _double(qvv) for qf, _, qvv in _fields(dv)}
                            # proto3 omits a 0.0 default on the wire
                            point["quantiles"][qv.get(1, 0.0)] = qv.get(2, 0.0)
                    out.append(point)
    return out


def _parses_as_json_lines(body):
    try:
        lines = [ln for ln in body.decode("utf-8").splitlines() if ln.strip()]
        return bool(lines) and all(isinstance(json.loads(ln), dict) for ln in lines)
    except (UnicodeDecodeError, ValueError):
        return False


# --- AWS plumbing ---
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
        Description="sim2real cwstreamfmt metric stream export",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": "cwstreamfmt"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=name)))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline")))
    return arn


def _delivery_stream(ctx, bucket, propagation_s):
    firehose = ctx.client("firehose")
    role_arn = _role(ctx, "fh", "firehose.amazonaws.com", {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                   "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}]})
    # IAM exposes no propagation condition; the bounded retry in _retry is what makes this correct,
    # this short sleep only makes the first attempt likelier to succeed.
    time.sleep(propagation_s)
    name = ctx.unique_name("sim2real-cwstreamfmt-")
    _retry(lambda: firehose.create_delivery_stream(
        DeliveryStreamName=name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": _PREFIX,
            "ErrorOutputPrefix": "sim2real-errors/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=[{"Key": "sim2real", "Value": "cwstreamfmt"}],
    ))
    ctx.on_cleanup(lambda: _teardown(lambda: firehose.delete_delivery_stream(
        DeliveryStreamName=name, AllowForceDelete=True)))
    arn = firehose.describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"]["DeliveryStreamARN"]
    return name, arn


def _await_active(firehose, name, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name!r} stalled in {status!r}")
        time.sleep(5.0)


def _list_objects(s3, bucket):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=_PREFIX):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry(fn, attempts=12, interval_s=5.0):
    """Bounded retry over the IAM-propagation window at first use of a new role."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") in (
                "AccessDenied", "AccessDeniedException", "InvalidArgumentException",
                "ValidationException",
            ) and any(w in msg for w in ("assume", "not authorized", "role", "iam"))
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
