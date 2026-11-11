"""metrics-states-stream-denied-role-delivery-metrics-stay-zero-control-matches-landed-bytes."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-stream-denied-role-delivery-metrics-stay-zero-control-matches-landed-bytes"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "firehose", "s3"]

_NAMESPACE = "AWS/Firehose"
_BUFFER_S = 60
_DELIVERY_BUDGET_S = 300.0
_METRIC_BUDGET_S = 360.0
_POLL_S = 15.0
_HOLD_S = 60.0
#: Distinct, non-round lengths so no "N x constant" reaches the byte total.
_PAYLOADS = tuple(
    (f"sim2real-fh-{i}-" + "z" * n + "\n").encode() for i, n in enumerate((5, 12, 19, 29, 37, 47, 61))
)
_N = len(_PAYLOADS)
_BYTES = sum(len(p) for p in _PAYLOADS)


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/monitoring-with-cloudwatch-metrics.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Two DirectPut streams take the same records: the control lands them and its DeliveryToS3
    Records and Bytes equal what S3 holds, while the stream whose role is denied s3:PutObject lands
    nothing and its DeliveryToS3 counters stay at 0."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = _bucket(ctx, s3)
    ok_role = _role(ctx, bucket, put=True)
    deny_role = _role(ctx, bucket, put=False)
    ok_stream = _stream(ctx, firehose, bucket, "ok/", ok_role, "ok-")
    deny_stream = _stream(ctx, firehose, bucket, "deny/", deny_role, "deny-")
    for s in (ok_stream, deny_stream):
        _wait_active(firehose, s)

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    for s in (ok_stream, deny_stream):
        resp = firehose.put_record_batch(DeliveryStreamName=s,
                                         Records=[{"Data": p} for p in _PAYLOADS])
        assert resp["FailedPutCount"] == 0, f"PutRecordBatch into {s} failed entries: {resp!r}"

    # Positive control: the permitted stream's bytes land, exactly.
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    landed = None
    while time.monotonic() < deadline:
        landed = _concat(s3, bucket, "ok/")
        if landed is not None and len(landed) >= _BYTES:
            break
        time.sleep(_POLL_S)
    assert landed is not None and len(landed) == _BYTES, (
        f"control stream delivered {None if landed is None else len(landed)} bytes to "
        f"s3://{bucket}/ok/ in {_DELIVERY_BUDGET_S}s; expected exactly {_BYTES}")
    for p in _PAYLOADS:
        assert p in landed, f"record {p!r} missing from the control's delivered bytes"

    ok_d = [{"Name": "DeliveryStreamName", "Value": ok_stream}]
    deny_d = [{"Name": "DeliveryStreamName", "Value": deny_stream}]
    want = {
        "ok IncomingRecords": float(_N),
        "deny IncomingRecords": float(_N),
        "ok DeliveryToS3.Records": float(_N),
        "ok DeliveryToS3.Bytes": float(len(landed)),
    }
    reads = {
        "ok IncomingRecords": ("IncomingRecords", ok_d),
        "deny IncomingRecords": ("IncomingRecords", deny_d),
        "ok DeliveryToS3.Records": ("DeliveryToS3.Records", ok_d),
        "ok DeliveryToS3.Bytes": ("DeliveryToS3.Bytes", ok_d),
    }

    def _read():
        r = {k: _sum(cw, m, d, window_start) for k, (m, d) in reads.items()}
        r["ok Success max"] = _max(cw, "DeliveryToS3.Success", ok_d, window_start)
        return r

    deadline = time.monotonic() + _METRIC_BUDGET_S
    got = None
    while time.monotonic() < deadline:
        got = _read()
        if {k: got[k] for k in want} == want and got["ok Success max"] > 0:
            break
        time.sleep(_POLL_S)
    assert got is not None and {k: got[k] for k in want} == want, (
        f"AWS/Firehose sums settled at {got!r}; expected {want!r}")
    assert got["ok Success max"] > 0, f"control DeliveryToS3.Success never exceeded 0: {got!r}"

    # Effect-absent, held past the barrier: the control's delivery is already counted, and the
    # denied stream ran on the same buffer interval.
    hold_until = time.monotonic() + _HOLD_S
    while True:
        objs = _keys(s3, bucket, "deny/")
        assert objs == [], f"the denied role still landed objects in s3://{bucket}/deny/: {objs!r}"
        moved = {m: v for m in ("DeliveryToS3.Records", "DeliveryToS3.Bytes", "DeliveryToS3.Success")
                 if (v := _max(cw, m, deny_d, window_start)) > 0}
        assert not moved, (
            f"delivery counters moved for the denied stream {deny_stream}: {moved!r} "
            f"(control settled at {got!r})")
        if time.monotonic() >= hold_until:
            break
        time.sleep(_POLL_S)


def _bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-behav-fhden-")
    kw: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)

    def _empty_and_delete() -> None:
        stop_at = time.monotonic() + 45.0
        while True:
            keys = [{"Key": k} for k in _keys(s3, name, "")]
            if not keys:
                break
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            if time.monotonic() >= stop_at:
                break
            time.sleep(3.0)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "1"}]})
    return name


def _role(ctx, bucket: str, put: bool) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fhden-role-")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": "1"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    actions = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]
    if put:
        actions += ["s3:PutObject", "s3:AbortMultipartUpload", "s3:GetObject"]
    iam.put_role_policy(RoleName=name, PolicyName="access", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions,
                       "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="access"))
    return arn


def _stream(ctx, firehose, bucket: str, prefix: str, role_arn: str, suffix: str) -> str:
    name = ctx.unique_name("sim2real-behav-fhden-" + suffix)
    config = {
        "RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}", "Prefix": prefix,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": _BUFFER_S},
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name, DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real", "Value": "1"}])
            ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
            return name
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last = exc
            time.sleep(10.0)  # Firehose cannot yet assume the fresh role; the retry is the wait
    raise AssertionError(f"CreateDeliveryStream {name} never accepted its role: {last!r}")


def _wait_active(firehose, name: str) -> None:
    deadline = time.monotonic() + 300.0
    status = None
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(
            DeliveryStreamName=name)["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        assert status not in ("CREATING_FAILED", "DELETING_FAILED"), f"{name} is {status}"
        time.sleep(10.0)
    raise AssertionError(f"delivery stream {name} still {status!r} after 300s")


def _keys(s3, bucket: str, prefix: str) -> list[str]:
    return [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=bucket, Prefix=prefix) for o in page.get("Contents", [])]


def _concat(s3, bucket: str, prefix: str) -> bytes | None:
    keys = sorted(_keys(s3, bucket, prefix))
    if not keys:
        return None
    return b"".join(s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in keys)


def _stats(cw, metric: str, dims: list, start, stat: str) -> list:
    return cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=[stat])["Datapoints"]


def _sum(cw, metric: str, dims: list, start) -> float:
    return float(sum(p["Sum"] for p in _stats(cw, metric, dims, start, "Sum")))


def _max(cw, metric: str, dims: list, start) -> float:
    return max((p["Maximum"] for p in _stats(cw, metric, dims, start, "Maximum")), default=0.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
