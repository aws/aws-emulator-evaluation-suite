"""metric-stream-stopped-from-creation-withholds-minutes-and-restart-does-not-replay."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-stream-stopped-from-creation-withholds-minutes-and-restart-does-not-replay"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_METRIC = "Gate"
_DIMENSIONS = {"Case": "gate"}
_VALUE = 42.0
_PREFIX = "metric-stream/"
_RECORD_KEYS = {
    "metric_stream_name",
    "account_id",
    "region",
    "namespace",
    "metric_name",
    "dimensions",
    "timestamp",
    "value",
    "unit",
}
_VALUE_KEYS = {"count", "sum", "max", "min"}
#: Metric minutes before the restart minute that a restarted stream may still export.
_QUIET_MINUTES = 2
_MINUTE_MS = 60_000
#: One deadline shared by every delivery wait in the check; it bounds, it is not the claim.
_CEILING_S = 540.0
_POLL_S = 2.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Metric-Streams.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A metric stream stopped before any datapoint exports none of the minutes a running twin
    delivers in the documented JSON record format; started again, it delivers new minutes in that
    format without replaying the minutes it was stopped for.
    """
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    # PutMetricStream assumes the role asynchronously, so the first barrier absorbs IAM propagation.
    left = ctx.time_left()
    ceiling_s = _CEILING_S if left is None else min(_CEILING_S, left)
    deadline = time.monotonic() + ceiling_s

    bucket = _bucket(ctx)
    firehose_arn = _delivery_stream(ctx, bucket)
    role_arn = _metric_stream_role(ctx, firehose_arn)
    namespace = ctx.unique_name("Sim2RealMsGate")
    subject = _metric_stream(ctx, namespace, firehose_arn, role_arn, "sub")
    cw.stop_metric_streams(Names=[subject])
    control = _metric_stream(ctx, namespace, firehose_arn, role_arn, "ctl")
    assert cw.get_metric_stream(Name=subject)["State"] == "stopped", "subject must read back stopped"
    assert cw.get_metric_stream(Name=control)["State"] == "running", "a new metric stream must be running"

    def publish() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": _METRIC,
                    "Dimensions": [{"Name": k, "Value": v} for k, v in _DIMENSIONS.items()],
                    "Timestamp": datetime.now(timezone.utc),
                    "Value": _VALUE,
                    "Unit": "Count",
                }
            ],
        )

    seen_objects: dict = {}

    def by_stream() -> dict:
        out: dict = {subject: [], control: []}
        for rec in _records(s3, bucket, seen_objects):
            if rec.get("namespace") == namespace and rec.get("metric_stream_name") in out:
                out[rec["metric_stream_name"]].append(rec)
        return out

    def poll(ready, description):
        while True:
            seen = by_stream()
            if ready(seen):
                return seen
            if time.monotonic() >= deadline:
                raise AssertionError(f"{description}: not reached within {ceiling_s}s; seen {_summary(seen)!r}")
            publish()
            time.sleep(_POLL_S)

    # ---- stopped: the control delivers the published minutes, the subject none of them ----
    first_ms = _minute_ms(datetime.now(timezone.utc))
    publish()
    # The restart waits until the control's earliest delivered minute lies before the replay
    # window's end (restart - quiet allowance): a just-created stream may not export its first
    # minute, so the window is anchored on a minute the control really delivered.
    def restart_due(o) -> bool:
        delivered = [m for m in _minutes(o[control]) if m >= first_ms]
        now_ms = _minute_ms(datetime.now(timezone.utc))
        return bool(delivered) and now_ms >= delivered[0] + (_QUIET_MINUTES + 1) * _MINUTE_MS

    stopped = poll(
        restart_due,
        f"the running control delivered a minute at least {_QUIET_MINUTES + 1} minutes before the restart",
    )
    _assert_record_format(ctx, stopped[control][0])
    assert stopped[subject] == [], (
        f"subject {subject!r}, stopped before any datapoint, delivered metric minutes "
        f"{_minutes(stopped[subject])!r}; control minutes {_minutes(stopped[control])!r}"
    )

    # ---- restarted: the subject delivers again ----
    cw.start_metric_streams(Names=[subject])
    assert cw.get_metric_stream(Name=subject)["State"] == "running", "subject must read back running"
    restart_ms = _minute_ms(datetime.now(timezone.utc))
    replay_end_ms = restart_ms - _QUIET_MINUTES * _MINUTE_MS
    assert replay_end_ms > first_ms, (
        f"the replay window [{first_ms}, {replay_end_ms}) is empty; the restart came too early"
    )
    final = poll(
        lambda o: any(r["timestamp"] >= restart_ms for r in o[subject]),
        f"the restarted subject delivered a metric minute at/after {restart_ms}",
    )
    _assert_record_format(ctx, next(r for r in final[subject] if r["timestamp"] >= restart_ms))
    in_window = sorted({r["timestamp"] for r in final[control] if first_ms <= r["timestamp"] < replay_end_ms})
    assert in_window, (
        f"the control delivered no minute in the stopped window [{first_ms}, {replay_end_ms}): "
        f"{_minutes(final[control])!r}; the absence below would be vacuous"
    )
    # What was withheld stays withheld: a start resumes export, it does not replay the stopped
    # minutes (the quiet allowance is granted before the restart minute).
    replayed = sorted({r["timestamp"] for r in final[subject] if r["timestamp"] < replay_end_ms})
    assert replayed == [], (
        f"restarted subject {subject!r} delivered metric minutes from while it was stopped: "
        f"{replayed!r} (control delivered {in_window!r} in that window)"
    )


def _assert_record_format(ctx, rec) -> None:
    assert set(rec) == _RECORD_KEYS, f"record fields {sorted(rec)!r}, expected {sorted(_RECORD_KEYS)!r}"
    assert rec["account_id"] == ctx.account, f"account_id {rec['account_id']!r}"
    assert rec["region"] == ctx.region, f"region {rec['region']!r}, expected {ctx.region!r}"
    assert rec["metric_name"] == _METRIC, f"metric_name {rec['metric_name']!r}"
    assert rec["dimensions"] == _DIMENSIONS, f"dimensions {rec['dimensions']!r}"
    assert rec["unit"] == "Count", f"unit {rec['unit']!r}"
    assert isinstance(rec["timestamp"], int) and rec["timestamp"] % _MINUTE_MS == 0, (
        f"timestamp must be an epoch-millisecond minute, got {rec['timestamp']!r}"
    )
    value = rec["value"]
    assert set(value) == _VALUE_KEYS, f"value keys {sorted(value)!r}, expected {sorted(_VALUE_KEYS)!r}"
    assert value["min"] == value["max"] == _VALUE, f"every datapoint is {_VALUE}, got {value!r}"
    assert value["count"] >= 1 and value["sum"] == value["count"] * _VALUE, (
        f"sum must be count * {_VALUE}, got {value!r}"
    )


def _minute_ms(moment) -> int:
    return int(moment.timestamp() * 1000) // _MINUTE_MS * _MINUTE_MS


def _minutes(records) -> list[int]:
    return sorted({r["timestamp"] for r in records})


def _summary(seen) -> dict:
    return {name: _minutes(recs) for name, recs in seen.items()}


def _records(s3, bucket, cache) -> list[dict]:
    """Every delivered record; `cache` keeps each object's records, as delivered objects never change."""
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=_PREFIX):
        for obj in page.get("Contents", []):
            if obj["Key"].startswith(f"{_PREFIX}errors/"):
                continue
            if obj["Key"] not in cache:
                body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                if body[:2] == b"\x1f\x8b":
                    body = gzip.decompress(body)
                cache[obj["Key"]] = _split_json(body.decode("utf-8"))
            out.extend(cache[obj["Key"]])
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


def _bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-msgate-")
    kw: dict = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
    return name


def _empty_and_delete_bucket(s3, bucket) -> None:
    """Firehose deletion is asynchronous and can flush one last object after the bucket was
    emptied, so empty-then-delete is retried over a bounded window."""
    deadline = time.monotonic() + 120.0
    while True:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            stale = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if stale:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": stale})
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _role(ctx, label, trust_service, policy_doc) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-msgate-{label}-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="permissions", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="permissions"))
    return arn


def _delivery_stream(ctx, bucket) -> str:
    firehose = ctx.client("firehose")
    role_arn = _role(
        ctx,
        "fh",
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
    name = ctx.unique_name("sim2real-msgate-fh-")
    _retry_iam(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket}",
                "Prefix": _PREFIX,
                "ErrorOutputPrefix": f"{_PREFIX}errors/",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=_TAGS,
        )
    )
    ctx.on_cleanup(lambda: _delete_delivery_stream(firehose, name))
    wait_deadline = time.monotonic() + 300.0
    while True:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        if time.monotonic() >= wait_deadline:
            raise AssertionError(f"delivery stream {name!r} stalled in {desc['DeliveryStreamStatus']!r}")
        time.sleep(2.0)


def _delete_delivery_stream(firehose, name, timeout_s=300.0) -> None:
    """Delete the delivery stream and wait until it is gone; only not-found means gone."""
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except firehose.exceptions.ResourceNotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = firehose.describe_delivery_stream(
                DeliveryStreamName=name)["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        except firehose.exceptions.ResourceNotFoundException:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name!r} still {status!r} {timeout_s}s after delete")
        time.sleep(5.0)


def _metric_stream_role(ctx, firehose_arn) -> str:
    arn = _role(
        ctx,
        "ms",
        "streams.metrics.cloudwatch.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": firehose_arn,
                }
            ],
        },
    )
    return arn


def _metric_stream(ctx, namespace, firehose_arn, role_arn, label) -> str:
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(f"sim2real-msgate-{label}-")
    # Registered BEFORE the call: PutMetricStream is an upsert.
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))
    cw.put_metric_stream(
        Name=name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": namespace}],
        Tags=_TAGS,
    )
    return name


def _retry_iam(fn, attempts=12, interval_s=5.0):
    """Bounded IAM-propagation retry at first use of a freshly created role."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidArgumentException" and "assume" in msg
            if not transient or i == attempts - 1:
                raise
            time.sleep(interval_s)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
