"""obs-cloudwatch-2-opentelemetry1-stream-lands-otlp-protobuf-and-exclude-filter-drops-namespace."""
from __future__ import annotations

import gzip
import json
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-cloudwatch-2-opentelemetry1-stream-lands-otlp-protobuf-and-exclude-filter-drops-namespace"
GROUP = "metric-streams-delivery"
SERVICES = ["cloudwatch", "firehose", "s3"]

_OTEL_METRIC = "OtelStreamedMetric"
_OTEL_VALUE = 4242.5
_JSON_METRIC = "IncludedMetric"
_JSON_VALUE = 31.0
_EXCL_METRIC = "ExcludedMetric"
_EXCL_VALUE = 17.0
_OTEL_PREFIX = "sim2real-obs2-otel/"
_JSON_PREFIX = "sim2real-obs2-json/"
_TRUSTED = "streams.metrics.cloudwatch.amazonaws.com"
_CEILING_S = 600.0
_POLL_S = 20.0


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """An opentelemetry1.0 stream lands OTLP protobuf; an ExcludeFilters stream drops one namespace.

    The OTLP object decodes as length-delimited ExportMetricsServiceRequest messages carrying the
    published Summary; the excluding stream lands no record of the namespace an including twin exports.
    """
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _bucket(ctx)
    otel_fh = _delivery_stream(ctx, bucket, _OTEL_PREFIX, "otel")
    json_fh = _delivery_stream(ctx, bucket, _JSON_PREFIX, "json")
    _await_active(ctx, [otel_fh, json_fh])
    role = _stream_role(ctx, [otel_fh["arn"], json_fh["arn"]], _TRUSTED, "otel")

    ns_otel = ctx.unique_name("Sim2RealObs2OtelNs")
    ns_json = ctx.unique_name("Sim2RealObs2JsonNs")
    ns_excl = ctx.unique_name("Sim2RealObs2ExclNs")

    otel = _metric_stream(ctx, otel_fh["arn"], role, "otel", "opentelemetry1.0",
                          IncludeFilters=[{"Namespace": ns_otel}])
    inc = _metric_stream(ctx, json_fh["arn"], role, "inc", "json",
                         IncludeFilters=[{"Namespace": ns_excl}])
    exc = _metric_stream(ctx, json_fh["arn"], role, "exc", "json",
                         ExcludeFilters=[{"Namespace": ns_excl}])
    described = {n: cw.get_metric_stream(Name=n) for n in (otel, inc, exc)}
    assert described[otel]["OutputFormat"] == "opentelemetry1.0", f"{described[otel]!r}"
    assert described[exc]["ExcludeFilters"] == [{"Namespace": ns_excl}], f"{described[exc]!r}"
    assert "IncludeFilters" not in described[exc] or not described[exc]["IncludeFilters"], (
        f"{described[exc]!r}")

    def publish():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        for ns, name, value in ((ns_otel, _OTEL_METRIC, _OTEL_VALUE),
                                (ns_json, _JSON_METRIC, _JSON_VALUE),
                                (ns_excl, _EXCL_METRIC, _EXCL_VALUE)):
            cw.put_metric_data(Namespace=ns, MetricData=[{
                "MetricName": name, "Timestamp": now, "Value": value,
                "Dimensions": [{"Name": "Shard", "Value": "s0"}]}])

    publish()

    def _observe():
        recs = _records(s3, bucket, _list_objects(s3, bucket, _JSON_PREFIX))
        inc_excl = [r for r in recs if r.get("metric_stream_name") == inc
                    and r.get("namespace") == ns_excl]
        exc_json = [r for r in recs if r.get("metric_stream_name") == exc
                    and r.get("namespace") == ns_json]
        return {
            "otel keys": _list_objects(s3, bucket, _OTEL_PREFIX),
            "inc excl": inc_excl,
            "exc json": exc_json,
            "shared minutes": {r["timestamp"] for r in inc_excl} & {
                r["timestamp"] for r in exc_json},
            "exc excl": [r for r in recs if r.get("metric_stream_name") == exc
                         and r.get("namespace") == ns_excl],
            "otel req": _otel_with(s3, bucket, _OTEL_PREFIX, _OTEL_METRIC),
        }

    seen = _poll(_observe, lambda o: o["otel req"] is not None and o["shared minutes"],
                 republish=publish,
                 description="the otel stream landed the published metric and the inc/exc "
                             "streams delivered in a shared metric minute")

    # ---- ExcludeFilters: absent, past the differential barrier ----
    assert seen["exc excl"] == [], (
        f"stream {exc!r} excludes {ns_excl!r} yet landed {len(seen['exc excl'])} record(s) for "
        f"it: {seen['exc excl'][:3]!r}")
    for rec in seen["inc excl"] + seen["exc json"]:
        assert isinstance(rec.get("dimensions"), dict) and rec["dimensions"] == {"Shard": "s0"}, (
            f"JSON record dimensions are {rec.get('dimensions')!r}, expected {{'Shard': 's0'}}")
        value = rec.get("value") or {}
        assert "sum" in value and "count" in value, f"JSON record value lacks sum/count: {rec!r}"
        want = _EXCL_VALUE if rec["namespace"] == ns_excl else _JSON_VALUE
        assert value["count"] >= 1 and value["sum"] == value["count"] * want, (
            f"value.sum {value['sum']!r} != value.count {value['count']!r} * {want!r}: {rec!r}")

    # ---- opentelemetry1.0: not NDJSON, and a complete OTLP decode ----
    key, body, reqs = seen["otel req"]
    head = body.lstrip()[:1]
    assert head != b"{", f"s3://{bucket}/{key} starts with {body[:40]!r}: that is JSON, not OTLP"
    first_line = body.split(b"\n", 1)[0]
    try:
        json.loads(first_line.decode("utf-8"))
        parsed_as_json = True
    except (UnicodeDecodeError, ValueError):
        parsed_as_json = False
    assert not parsed_as_json, f"first line of s3://{bucket}/{key} parses as JSON: {first_line!r}"

    points = [p for req in reqs for p in _points(req, _OTEL_METRIC)]
    assert points, f"no OTLP metric named like {_OTEL_METRIC!r} in s3://{bucket}/{key}: {reqs!r}"
    mine = [p for p in points if ns_otel in _strings(p["attributes"]) + [p["metric"]]]
    assert mine, (f"OTLP datapoints for {_OTEL_METRIC!r} never name namespace {ns_otel!r}: "
                  f"{points!r}")
    for p in mine:
        assert p["kind"] == "summary", f"expected a Summary datapoint, got {p!r}"
        assert p["count"] >= 1 and p["sum"] == p["count"] * _OTEL_VALUE, (
            f"OTLP summary sum {p['sum']!r} != count {p['count']!r} * {_OTEL_VALUE!r}: {p!r}")
        quantiles = dict(p["quantiles"])
        assert quantiles.get(0.0) == _OTEL_VALUE and quantiles.get(1.0) == _OTEL_VALUE, (
            f"OTLP quantiles {p['quantiles']!r}, expected 0.0 and 1.0 == {_OTEL_VALUE!r}")
        assert account_id in _strings(p["resource"]), (
            f"OTLP resource attributes {p['resource']!r} do not carry account {account_id!r}")


# ===== helpers =====
# A minimal protobuf wire-format reader, so the OTLP decode needs only the standard library (no
# protobuf / opentelemetry-proto dependency).
def _varint(buf, i):
    shift = value = 0
    while True:
        if i >= len(buf):
            raise ValueError(f"truncated varint at {i}")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError(f"varint too long at {i}")


def _fields(buf):
    """[(field_number, wire_type, value)] for one message; raises on any malformed byte."""
    out, i = [], 0
    while i < len(buf):
        tag, i = _varint(buf, i)
        num, wt = tag >> 3, tag & 7
        if num == 0:
            raise ValueError(f"field number 0 at {i}")
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            if i + 8 > len(buf):
                raise ValueError("truncated fixed64")
            v, i = buf[i:i + 8], i + 8
        elif wt == 2:
            n, i = _varint(buf, i)
            if i + n > len(buf):
                raise ValueError(f"length {n} overruns message at {i}")
            v, i = buf[i:i + n], i + n
        elif wt == 5:
            if i + 4 > len(buf):
                raise ValueError("truncated fixed32")
            v, i = buf[i:i + 4], i + 4
        else:
            raise ValueError(f"unsupported wire type {wt} at {i}")
        out.append((num, wt, v))
    return out


def _sub(buf, num):
    return [v for n, wt, v in _fields(buf) if n == num and wt == 2]


def _any_value(buf):
    for n, wt, v in _fields(buf):
        if n == 1 and wt == 2:
            return v.decode("utf-8")
        if n == 2 and wt == 0:
            return bool(v)
        if n == 3 and wt == 0:
            return v
        if n == 4 and wt == 1:
            return struct.unpack("<d", v)[0]
        if n == 5 and wt == 2:
            return [_any_value(x) for x in _sub(v, 1)]
        if n == 6 and wt == 2:
            return _kvs(v, 1)
    return None


def _kvs(buf, num) -> dict:
    out = {}
    for kv in _sub(buf, num):
        key = next((v.decode("utf-8") for n, wt, v in _fields(kv) if n == 1 and wt == 2), "")
        val = next((_any_value(v) for n, wt, v in _fields(kv) if n == 2 and wt == 2), None)
        out[key] = val
    return out


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in [k] + _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def _points(req, metric_name) -> list[dict]:
    """Datapoints of every Metric whose name ends with metric_name, from one
    ExportMetricsServiceRequest (1: resource_metrics -> 1: resource{1: attributes},
    2: scope_metrics -> 2: metrics{1: name, 5: gauge, 7: sum, 9: histogram, 11: summary})."""
    out = []
    for rm in _sub(req, 1):
        resource = {}
        for res in _sub(rm, 1):
            resource.update(_kvs(res, 1))
        for sm in _sub(rm, 2):
            for metric in _sub(sm, 2):
                fields = _fields(metric)
                name = next((v.decode("utf-8") for n, wt, v in fields if n == 1 and wt == 2), "")
                if not name.endswith(metric_name):
                    continue
                kinds = {n for n, wt, v in fields if wt == 2 and n in (5, 7, 9, 10, 11)}
                for summary in [v for n, wt, v in fields if n == 11 and wt == 2]:
                    for dp in _sub(summary, 1):
                        p = {"kind": "summary", "metric": name, "resource": resource,
                             "attributes": _kvs(dp, 7), "count": 0, "sum": None, "quantiles": []}
                        for n, wt, v in _fields(dp):
                            if n == 4 and wt == 1:
                                p["count"] = struct.unpack("<Q", v)[0]
                            elif n == 5 and wt == 1:
                                p["sum"] = struct.unpack("<d", v)[0]
                            elif n == 6 and wt == 2:
                                q = {qn: struct.unpack("<d", qv)[0] for qn, qwt, qv in _fields(v)
                                     if qwt == 1}
                                p["quantiles"].append((q.get(1, 0.0), q.get(2, 0.0)))
                        out.append(p)
                if 11 not in kinds:
                    out.append({"kind": f"fields {sorted(kinds)}", "metric": name,
                                "resource": resource, "attributes": {}, "count": 0, "sum": None,
                                "quantiles": []})
    return out


def _otlp_frames(body) -> list[bytes]:
    """Split an object into varint-length-delimited messages; the frames must consume EVERY byte."""
    frames, i = [], 0
    while i < len(body):
        n, i = _varint(body, i)
        if n == 0 or i + n > len(body):
            raise ValueError(f"frame length {n} at {i} overruns the {len(body)}-byte object")
        frames.append(body[i:i + n])
        i += n
    return frames


def _otel_with(s3, bucket, prefix, metric_name):
    """(key, body, [request bytes]) for the first landed object that decodes completely as OTLP
    and contains metric_name; None while nothing like that has landed. A decode failure is a FAIL,
    not a retry: a landed object that is not OTLP is the defect under test."""
    for key in _list_objects(s3, bucket, prefix):
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        try:
            reqs = _otlp_frames(body)
            for req in reqs:
                _fields(req)
        except ValueError as exc:
            raise AssertionError(
                f"s3://{bucket}/{key} is not length-delimited OTLP ({exc}); first bytes "
                f"{body[:60]!r}") from exc
        if any(_points(r, metric_name) for r in reqs):
            return key, body, reqs
    return None


def _poll(observe, ready, *, republish, description):
    deadline = time.monotonic() + _CEILING_S
    while True:
        seen = observe()
        if ready(seen):
            return seen
        if time.monotonic() >= deadline:
            brief = {k: (v if not isinstance(v, list) else v[:3]) for k, v in seen.items()}
            raise AssertionError(f"{description}: not reached within {_CEILING_S}s; last {brief!r}")
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


def _metric_stream(ctx, firehose_arn, role_arn, label, output_format, **filters) -> str:
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(f"sim2real-obs2-{label}-")
    # Registered BEFORE the call: PutMetricStream is an upsert with no synchronous validation.
    ctx.on_cleanup(lambda: _teardown(lambda: cw.delete_metric_stream(Name=name)))
    _retry(lambda: cw.put_metric_stream(
        Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat=output_format,
        Tags=[{"Key": "sim2real", "Value": "obs2"}], **filters,
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
