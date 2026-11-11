"""incoming-records-and-delivery-to-s3-join-the-put-to-the-delivered-object."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "incoming-records-and-delivery-to-s3-join-the-put-to-the-delivered-object"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "firehose", "s3"]

#: Nine records of DISTINCT, non-round payload lengths. The byte total is not a multiple of the
#: record count, so a target reporting "N * a constant size" cannot land on it.
_PAYLOADS = tuple(
    (f"sim2real-firehose-record-{i}-" + "x" * n + "\n").encode("utf-8")
    for i, n in enumerate((7, 11, 17, 23, 31, 43, 53, 67, 79))
)
_N_RECORDS = len(_PAYLOADS)
_BYTES = float(sum(len(p) for p in _PAYLOADS))

_BUFFER_INTERVAL_S = 60
_DELIVERY_BUDGET_S = 420.0
_METRIC_BUDGET_S = 900.0
_ROLE_PROPAGATION_BUDGET_S = 180.0


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/monitoring-with-cloudwatch-metrics.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """PutRecordBatch's records and bytes appear exactly in AWS/Firehose IncomingRecords/IncomingBytes,
    DeliveryToS3.Records equals what landed in the bucket, and DataFreshness is bounded by the measured
    put->object latency: a target counting delivery from the request alone fails the bucket anchor."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_firehose_role(ctx, bucket)
    prefix = "sim2real/"

    stream = ctx.unique_name("sim2real-cwfh-")
    # The role is brand new: Firehose's own AssumeRole is subject to IAM propagation, so
    # CreateDeliveryStream is retried on the documented transient refusal rather than slept past.
    _create_stream_when_role_is_assumable(
        ctx, firehose, stream, bucket=bucket, prefix=prefix, role_arn=role_arn
    )
    _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
        description=f"delivery stream {stream} reaching ACTIVE",
        terminal_bad={"CREATING_FAILED", "DELETING_FAILED"},
    )

    # ---- drive exactly the traffic we will demand an account of ------------------------------ #
    put_at = time.monotonic()
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream, Records=[{"Data": p} for p in _PAYLOADS]
    )
    assert resp["FailedPutCount"] == 0, (
        f"PutRecordBatch reported {resp['FailedPutCount']} failed puts of {_N_RECORDS} "
        f"({resp!r}); no metric total below would then be attributable to this check"
    )
    assert len(resp["RequestResponses"]) == _N_RECORDS, (
        f"PutRecordBatch returned {len(resp['RequestResponses'])} per-record results, expected "
        f"{_N_RECORDS}: {resp!r}"
    )

    # ---- leg 1: the bytes really landed, and we time how long that took ----------------------- #
    delivered_bytes = _poll_until(
        lambda: _concat_objects(s3, bucket, prefix),
        lambda blob: blob is not None and len(blob) >= int(_BYTES),
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=15.0,
        description=(
            f"Firehose flushing its {_BUFFER_INTERVAL_S}s buffer into s3://{bucket}/{prefix} "
            f"({int(_BYTES)} bytes across {_N_RECORDS} records)"
        ),
    )
    visible_after_s = time.monotonic() - put_at
    for payload in _PAYLOADS:
        assert payload in delivered_bytes, (
            f"record {payload!r} is not present in the delivered S3 bytes "
            f"({len(delivered_bytes)} bytes total); the metric totals below are only meaningful "
            f"against a delivery that actually happened"
        )
    assert len(delivered_bytes) == int(_BYTES), (
        f"the delivered S3 objects total {len(delivered_bytes)} bytes, expected exactly "
        f"{int(_BYTES)} — Firehose for a DirectPut/ExtendedS3 stream with no transformation must "
        f"concatenate the record payloads without adding or dropping bytes"
    )

    # ---- leg 2: the terminal read, at CloudWatch --------------------------------------------- #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=25)

    def _dps(metric: str, *, stat: str = "Sum") -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/Firehose",
            MetricName=metric,
            Dimensions=[{"Name": "DeliveryStreamName", "Value": stream}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=[stat, "Maximum", "SampleCount"],
        )["Datapoints"]

    def _sum(metric: str) -> float | None:
        dps = _dps(metric)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    # Stability, not "poll until >= N": the failure mode of a target that double-counts a batch is
    # an OVER-count, which a one-sided poll cannot see because it stops at the first sufficient read.
    incoming_records, incoming_bytes, s3_records = _poll_until_stable(
        lambda: _triple(
            _sum("IncomingRecords"), _sum("IncomingBytes"), _sum("DeliveryToS3.Records")
        ),
        window_s=150.0,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=20.0,
        description=(
            f"AWS/Firehose IncomingRecords / IncomingBytes / DeliveryToS3.Records for "
            f"DeliveryStreamName={stream} settling on one value"
        ),
    )

    assert incoming_records == float(_N_RECORDS), (
        f"AWS/Firehose IncomingRecords Sum for DeliveryStreamName={stream} settled at "
        f"{incoming_records!r}, expected {float(_N_RECORDS)} — the number of records this check's "
        f"single PutRecordBatch was told it accepted"
    )
    assert incoming_bytes == _BYTES, (
        f"AWS/Firehose IncomingBytes Sum for DeliveryStreamName={stream} settled at "
        f"{incoming_bytes!r}, expected {_BYTES} — the byte total of the {_N_RECORDS} payloads, "
        f"whose lengths are all distinct and non-round so no per-record constant reaches it"
    )
    assert s3_records == float(_N_RECORDS), (
        f"AWS/Firehose DeliveryToS3.Records Sum for DeliveryStreamName={stream} settled at "
        f"{s3_records!r}, expected {float(_N_RECORDS)}. This is the leg anchored to the bucket: "
        f"{len(delivered_bytes)} bytes for {_N_RECORDS} records were independently read out of "
        f"s3://{bucket}/{prefix} before this assertion ran"
    )

    success = _dps("DeliveryToS3.Success")
    assert success, (
        f"AWS/Firehose DeliveryToS3.Success has no datapoint for DeliveryStreamName={stream}, yet "
        f"{len(delivered_bytes)} bytes were read back out of the bucket — a delivery that happened "
        f"and was not reported as a success"
    )
    assert max(d["Maximum"] for d in success) > 0.0, (
        f"AWS/Firehose DeliveryToS3.Success never exceeded 0 for DeliveryStreamName={stream} "
        f"({success!r}) although the objects are present in s3://{bucket}/{prefix}"
    )

    # DataFreshness as a DERIVATION RULE against this run's own measured clock, never a literal.
    freshness = _dps("DeliveryToS3.DataFreshness", stat="Maximum")
    assert freshness, (
        f"AWS/Firehose DeliveryToS3.DataFreshness has no datapoint for "
        f"DeliveryStreamName={stream}; the age of the oldest undelivered record is the metric every "
        f"Firehose backlog alarm is built on"
    )
    observed_max = max(d["Maximum"] for d in freshness)
    ceiling = visible_after_s + _BUFFER_INTERVAL_S
    assert 0.0 <= observed_max <= ceiling, (
        f"AWS/Firehose DeliveryToS3.DataFreshness peaked at {observed_max!r}s for "
        f"DeliveryStreamName={stream}; this check measured the put->object-visible latency as "
        f"{visible_after_s:.1f}s, so with the {_BUFFER_INTERVAL_S}s buffering interval the peak "
        f"freshness cannot exceed {ceiling:.1f}s. A constant or zero value fails this bound"
    )

    for metric, want_unit in (
        ("IncomingRecords", "Count"),
        ("IncomingBytes", "Bytes"),
        ("DeliveryToS3.Records", "Count"),
        ("DeliveryToS3.DataFreshness", "Seconds"),
    ):
        dps = _dps(metric)
        assert dps, f"AWS/Firehose {metric} vanished on re-read for {stream}: {dps!r}"
        units = {d.get("Unit") for d in dps}
        assert units == {want_unit}, (
            f"AWS/Firehose {metric} datapoints for DeliveryStreamName={stream} carry Unit(s) "
            f"{units!r}, expected exactly {{{want_unit!r}}} — a byte count reported as Count or a "
            f"latency reported as Milliseconds is invisible to any assertion on the value alone"
        )

    # A DirectPut/ExtendedS3 stream publishes its ingestion
    # metrics under BOTH the plain per-stream dimension set AND a second one that adds
    # SourcePartitionId — Firehose partitions ingestion capacity internally even for DirectPut, so
    # IncomingRecords/IncomingBytes get a per-partition breakdown alongside the per-stream total.
    # DeliveryStreamName remains the required filter key on every set; SourcePartitionId is the only
    # documented companion, so the two-member superset is pinned rather than left open-ended.
    published = _dimension_sets(cw, "AWS/Firehose", "DeliveryStreamName", stream)
    allowed_dimension_sets = {("DeliveryStreamName",), ("DeliveryStreamName", "SourcePartitionId")}
    assert published and published <= allowed_dimension_sets, (
        f"ListMetrics reports dimension sets {sorted(published)!r} for the AWS/Firehose series "
        f"naming DeliveryStreamName={stream}, expected a non-empty subset of "
        f"{sorted(allowed_dimension_sets)!r} — every set must be filterable by DeliveryStreamName "
        f"and no other dimension key is documented for this destination type"
    )
    assert ("DeliveryStreamName",) in published, (
        f"ListMetrics reports only {sorted(published)!r} for DeliveryStreamName={stream}; the plain "
        f"per-stream dimension set (with no SourcePartitionId) is the one every dashboard and alarm "
        f"filters on and must always be present"
    )


# ===== helpers =====
def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-cwfh-")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "cloudwatch__firehose__s3"}]},
    )

    def _empty_and_delete() -> None:
        # Firehose may still be flushing when teardown starts, so the empty is repeated until a
        # listing comes back clean (or the cleanup deadline is reached) rather than attempted once.
        # The 45s ceiling fits the 60s cleanup budget.
        stop_at = time.monotonic() + 45.0
        while True:
            keys = [
                {"Key": o["Key"]}
                for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name)
                for o in page.get("Contents", [])
            ]
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
    return name


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-cwfh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": account}},
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__firehose__s3"}],
    )["Role"]["Arn"]
    policy_name = "sim2real-firehose-s3"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
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
                        "Resource": [
                            f"arn:aws:s3:::{bucket}",
                            f"arn:aws:s3:::{bucket}/*",
                        ],
                    }
                ],
            }
        ),
    )
    # Reverse dependency order.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return arn


def _create_stream_when_role_is_assumable(
    ctx, firehose, stream: str, *, bucket: str, prefix: str, role_arn: str
) -> None:
    """CreateDeliveryStream, retried while IAM propagation keeps Firehose from assuming the role.

    Not an `except: pass`: only the documented transient refusal is retried, the retry is bounded by
    a deadline that RAISES, and any other error propagates immediately.
    """
    from botocore.exceptions import ClientError

    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": _BUFFER_INTERVAL_S},
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real", "Value": "cloudwatch__firehose__s3"}],
            )
            ctx.on_cleanup(
                lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream)
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidArgumentException":
                raise
            last = exc
            time.sleep(10.0)
    raise AssertionError(
        f"CreateDeliveryStream for {stream} never accepted role {role_arn} within "
        f"{_ROLE_PROPAGATION_BUDGET_S}s of IAM propagation retries; last refusal was {last!r}"
    )


def _concat_objects(s3, bucket: str, prefix: str) -> bytes | None:
    """Every object under *prefix*, concatenated in key order. None while the prefix is empty."""
    keys = [
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    ]
    if not keys:
        return None
    blob = b""
    for key in sorted(keys):
        blob += s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return blob


def _triple(a, b, c):
    return None if a is None or b is None or c is None else (a, b, c)


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until(
    probe, predicate, *, timeout_s, interval_s, description, terminal_bad=frozenset()
):
    """Poll until predicate(probe()) holds. Raises on the deadline and on a terminal bad value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last in terminal_bad:
            raise AssertionError(
                f"{description}: reached the terminal failure value {last!r}, which the poll's "
                f"target set excludes"
            )
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=20.0, description="reading"):
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
