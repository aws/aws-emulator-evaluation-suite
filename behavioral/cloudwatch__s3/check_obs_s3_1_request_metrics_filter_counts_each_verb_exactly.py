"""obs-s3-1-request-metrics-filter-counts-each-verb-exactly."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.config import Config

from behavioral_harness import tags

CHECK = "obs-s3-1-request-metrics-filter-counts-each-verb-exactly"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "s3"]

#: The one metrics configuration every assertion in this check reads. Its Id IS the FilterId
#: dimension value, and it is scoped to ``_PREFIX`` so only traffic under that prefix counts.
_FILTER_ID = "sim2realobsverbs"
_PREFIX = "obs/"

#: Three PutObject bodies of distinct, non-round sizes, so BytesUploaded can only be hit exactly by
#: a target that sums the real payload lengths.
_PUT_SIZES = (131, 977, 2053)
_GETS = 5
_HEADS = 2
_DELETES = 1
_MISSING_GETS = 2

#: The window must be at least this far past the last barrier request, so a barrier datapoint
#: stamped a minute late cannot land inside the measured window.
_QUIET_GAP_S = 120


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A known PUT/GET/HEAD/DELETE/LIST burst under a prefix filter is counted exactly per verb in
    AWS/S3 [BucketName, FilterId], with fixed units and AllRequests as the sum of the verbs.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html
    """
    # Checksums only where an operation REQUIRES one. With botocore's default ("when_supported")
    # every PutObject body is sent aws-chunked with a CRC32 trailer, and S3 counts those framing
    # bytes in BytesUploaded -- measured: 3 PUTs of 971 payload bytes reported 1099. Plain
    # Content-Length uploads make the payload the only thing on the wire.
    s3 = ctx.client("s3", config=Config(request_checksum_calculation="when_required",
                                        response_checksum_validation="when_required"))
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2real-obs-s3-verbs-")
    create_kwargs: dict = {"Bucket": bucket}
    # Transport-only region fork: us-east-1 rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=_FILTER_ID,
        MetricsConfiguration={"Id": _FILTER_ID, "Filter": {"Prefix": _PREFIX}},
    )
    ctx.on_cleanup(
        lambda: ctx.client("s3").delete_bucket_metrics_configuration(Bucket=bucket, Id=_FILTER_ID)
    )
    stored = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=_FILTER_ID)[
        "MetricsConfiguration"
    ]
    assert stored["Id"] == _FILTER_ID and stored["Filter"].get("Prefix") == _PREFIX, (
        f"metrics configuration read back as {stored!r}, expected Id {_FILTER_ID!r} with "
        f"prefix {_PREFIX!r}"
    )

    # Request metrics take up to ~15 minutes to start flowing and no API reports enablement, so
    # drive a barrier until the FilterId shows datapoints and appears in ListMetrics.
    # GETs, not ListObjectsV2: measured on real AWS, a ListObjectsV2 carrying Prefix=<filter
    # prefix> is never attributed to a prefix filter, so a LIST-only barrier waits forever.
    barrier_key = f"{_PREFIX}barrier-object"
    s3.put_object(Bucket=bucket, Key=barrier_key, Body=b"sim2real-barrier")
    last_barrier = {"t": time.time()}

    def _barrier_traffic() -> None:
        s3.get_object(Bucket=bucket, Key=barrier_key)["Body"].read()
        last_barrier["t"] = time.time()

    def _probe() -> tuple[list[dict], list[dict]]:
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        return _stats(cw, bucket, "AllRequests", ["Sum"], since), _list_metrics(cw, bucket)

    def _flowing(obs: tuple[list[dict], list[dict]]) -> bool:
        datapoints, listed = obs
        ids = {d["Value"] for m in listed for d in m["Dimensions"] if d["Name"] == "FilterId"}
        return bool(datapoints) and _FILTER_ID in ids

    _barrier_traffic()
    _, listed = _poll_until(
        _probe, _flowing, timeout_s=1500.0, interval_s=60.0,
        description=(
            f"AWS/S3 AllRequests datapoints for [BucketName={bucket}, FilterId={_FILTER_ID}] AND "
            f"the FilterId indexed by ListMetrics (request metrics take up to ~15 min to start "
            f"after PutBucketMetricsConfiguration)"
        ),
        on_iteration=_barrier_traffic,
    )
    dims_seen = {tuple(sorted(d["Name"] for d in m["Dimensions"])) for m in listed}
    assert dims_seen == {("BucketName", "FilterId")}, (
        f"ListMetrics reports AWS/S3 dimension combos {sorted(dims_seen)!r} for this bucket; "
        f"request metrics for a filtered configuration are published under exactly "
        f"[BucketName, FilterId]"
    )

    # Window alignment, not a wait-for-condition: CloudWatch buckets datapoints per minute, so
    # the window must start on a boundary the barrier cannot reach.
    open_at = (int((last_barrier["t"] + _QUIET_GAP_S) // 60) + 1) * 60 + 2
    time.sleep(max(0.0, open_at - time.time()))
    window_start = datetime.fromtimestamp(open_at - 2, tz=timezone.utc)

    keys = [f"{_PREFIX}object-{i}" for i in range(len(_PUT_SIZES))]
    for key, size in zip(keys, _PUT_SIZES):
        s3.put_object(Bucket=bucket, Key=key, Body=b"o" * size)
    downloaded = 0
    for i in range(_GETS):
        body = s3.get_object(Bucket=bucket, Key=keys[i % len(keys)])["Body"].read()
        downloaded += len(body)
        assert len(body) == _PUT_SIZES[i % len(keys)], (
            f"GET {keys[i % len(keys)]!r} returned {len(body)} bytes, expected "
            f"{_PUT_SIZES[i % len(keys)]}"
        )
    for _ in range(_HEADS):
        s3.head_object(Bucket=bucket, Key=keys[0])
    s3.delete_object(Bucket=bucket, Key=keys[-1])
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=_PREFIX)
    listed_keys = sorted(o["Key"] for o in listing.get("Contents", []))
    assert listed_keys == sorted(keys[:-1] + [barrier_key]), (
        f"ListObjectsV2 under {_PREFIX!r} returned {listed_keys!r} after deleting {keys[-1]!r}"
    )
    for _ in range(_MISSING_GETS):
        err = _error(lambda: s3.get_object(Bucket=bucket, Key=f"{_PREFIX}absent-key"))
        assert err == ("NoSuchKey", "The specified key does not exist."), (
            f"GET of a missing key raised {err!r}, expected "
            f"('NoSuchKey', 'The specified key does not exist.')"
        )
    window_closed = time.time()

    # Real AWS behaviour:
    #   * GetRequests counts every GET under the prefix, including the 404s -- and NOT the HEADs,
    #     which are counted only in HeadRequests.
    #   * a ListObjectsV2 carrying Prefix=<the filter prefix> is NOT attributed to a prefix
    #     filter at all: no ListRequests datapoint ever appears (nor in ListMetrics), and it is not
    #     in AllRequests. So AllRequests == PUT + GET + HEAD + DELETE, and ListRequests is absent.
    expected = {
        "PutRequests": float(len(_PUT_SIZES)),
        "GetRequests": float(_GETS + _MISSING_GETS),
        "HeadRequests": float(_HEADS),
        "DeleteRequests": float(_DELETES),
        "4xxErrors": float(_MISSING_GETS),
        "5xxErrors": 0.0,
        "BytesUploaded": float(sum(_PUT_SIZES)),
    }
    expected["AllRequests"] = (
        expected["PutRequests"] + expected["GetRequests"] + expected["HeadRequests"]
        + expected["DeleteRequests"]
    )

    # Read until two consecutive passes agree and every count is in.
    def _window() -> dict[str, float | None]:
        out: dict[str, float | None] = {}
        for metric in expected:
            dps = _stats(cw, bucket, metric, ["Sum"], window_start)
            out[metric] = sum(float(d["Sum"]) for d in dps) if dps else None
        return out

    history: list[dict] = []

    def _settled(obs: dict) -> bool:
        history.append(obs)
        complete = obs["AllRequests"] is not None and obs["AllRequests"] >= expected["AllRequests"]
        return complete and len(history) >= 2 and history[-2] == obs

    observed = _poll_until(
        _window, _settled, timeout_s=900.0, interval_s=60.0,
        description=(
            f"the AWS/S3 window starting {window_start.isoformat()} for FilterId {_FILTER_ID!r} "
            f"to accumulate AllRequests >= {expected['AllRequests']} and hold steady for two passes"
        ),
    )

    list_dps = _stats(cw, bucket, "ListRequests", ["Sum"], window_start)
    assert list_dps == [], (
        f"ListRequests for FilterId {_FILTER_ID!r} has datapoints {list_dps!r}; real AWS does not "
        f"attribute a ListObjectsV2(Prefix={_PREFIX!r}) to a prefix filter"
    )
    for metric, want in expected.items():
        assert observed[metric] == want, (
            f"Sum({metric}) over the measured window is {observed[metric]!r}, expected {want!r}. "
            f"Burst issued between {window_start.isoformat()} and "
            f"{datetime.fromtimestamp(window_closed, tz=timezone.utc).isoformat()}: "
            f"{len(_PUT_SIZES)} PUT of {list(_PUT_SIZES)} bytes, {_GETS} GET, {_HEADS} HEAD, "
            f"{_DELETES} DELETE, 1 ListObjectsV2, {_MISSING_GETS} GET of a missing key. "
            f"Full window: {observed!r}"
        )

    for metric, unit in (("PutRequests", "Count"), ("4xxErrors", "Count"),
                         ("BytesUploaded", "Bytes")):
        units = {d["Unit"] for d in _stats(cw, bucket, metric, ["Sum"], window_start)}
        assert units == {unit}, f"{metric} datapoints report units {sorted(units)!r}, expected {unit!r}"

    # BytesDownloaded also counts the 404 error bodies (measured), whose length depends on the
    # request id, so only the successful payloads are a floor.
    down_dps = _stats(cw, bucket, "BytesDownloaded", ["Sum"], window_start)
    down = sum(float(d["Sum"]) for d in down_dps)
    assert {d["Unit"] for d in down_dps} == {"Bytes"} and down >= float(downloaded), (
        f"BytesDownloaded over the window is {down!r} ({down_dps!r}); the {_GETS} successful GETs "
        f"alone returned {downloaded} bytes"
    )
    for metric in ("FirstByteLatency", "TotalRequestLatency"):
        dps = _stats(cw, bucket, metric, ["Average", "Maximum", "SampleCount"], window_start)
        assert dps, f"no {metric} datapoints in the measured window for FilterId {_FILTER_ID!r}"
        units = {d["Unit"] for d in dps}
        assert units == {"Milliseconds"}, (
            f"{metric} datapoints report units {sorted(units)!r}, expected 'Milliseconds'"
        )
        peak = max(float(d["Maximum"]) for d in dps)
        assert 0.0 < peak < 60_000.0, (
            f"{metric} Maximum over the window is {peak!r} ms; a real request is neither "
            f"instantaneous nor over a minute. Datapoints: {dps!r}"
        )

    # A BucketName-only query must see none of the filter's datapoints.
    bucket_only = cw.get_metric_statistics(
        Namespace="AWS/S3", MetricName="AllRequests",
        Dimensions=[{"Name": "BucketName", "Value": bucket}],
        StartTime=window_start - timedelta(minutes=30),
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]
    assert bucket_only == [], (
        f"AllRequests queried on [BucketName] alone returned {bucket_only!r}; request metrics "
        f"are only published under [BucketName, FilterId], so a target that also emits a "
        f"bucket-only series is inventing one"
    )


def _stats(cw, bucket: str, metric: str, statistics: list[str], since: datetime) -> list[dict]:
    """GetMetricStatistics on EXACTLY [BucketName, FilterId] from *since* to a little past now."""
    return cw.get_metric_statistics(
        Namespace="AWS/S3",
        MetricName=metric,
        Dimensions=[{"Name": "BucketName", "Value": bucket},
                    {"Name": "FilterId", "Value": _FILTER_ID}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=statistics,
    )["Datapoints"]


def _list_metrics(cw, bucket: str) -> list[dict]:
    out = []
    for page in cw.get_paginator("list_metrics").paginate(
        Namespace="AWS/S3", Dimensions=[{"Name": "BucketName", "Value": bucket}]
    ):
        out.extend(page["Metrics"])
    return out


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - botocore ClientError and modelled subclasses
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call succeeded but an error was expected")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        entries = [{"Key": i["Key"], "VersionId": i["VersionId"]}
                   for g in ("Versions", "DeleteMarkers") for i in page.get(g, [])]
        if entries:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": entries})
    s3.delete_bucket(Bucket=bucket)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
