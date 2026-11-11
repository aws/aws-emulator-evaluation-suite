"""s3-request-metrics-filter-partitions-traffic-into-cloudwatch."""
from __future__ import annotations

# S3 request metrics are best-effort: "The data point for a minute might be delayed ... or it might
# not be delivered at all." So no claim here is an exact count: each is relative (busy > quiet over
# a sustained 6:1 ratio) or monotone-safe (loss can only remove datapoints, never manufacture one).
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "s3-request-metrics-filter-partitions-traffic-into-cloudwatch"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "s3"]

#: Three prefixes, three metrics configurations; the Ids are the FilterId dimension values.
_BUSY_ID = "sim2realbusyprefix"
_QUIET_ID = "sim2realquietprefix"
_SILENT_ID = "sim2realsilentprefix"
_CONFIGS = {_BUSY_ID: "busy/", _QUIET_ID: "quiet/", _SILENT_ID: "silent/"}

#: A 6:1 ratio, re-driven on every traffic pass across the enablement wait.
_BUSY_GETS_PER_PASS = 12
_QUIET_GETS_PER_PASS = 2

#: Distinctive, non-round payload sizes so a BytesDownloaded floor cannot be hit by a constant.
_BUSY_BODY = b"sim2real-busy-" + b"b" * 971
_QUIET_BODY = b"sim2real-quiet-" + b"q" * 313
_SILENT_BODY = b"sim2real-silent-" + b"s" * 107

#: Readiness re-poll cadence: short, so a series that lands just after a probe is seen promptly.
_POLL_S = 2.0
#: Traffic re-drive cadence during the readiness poll: one pass per 60 s period.
_DRIVE_EVERY_S = 60.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Three prefix-filtered metrics configurations on one bucket get separate FilterId series: a
    busy prefix out-counts a quiet one in GetRequests, a never-read prefix has none, units are Count
    and Bytes, and only the prefix that saw 404s reports a non-zero 4xxErrors sum.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html
    """
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2real-cw-s3-reqmetrics-")

    # CreateBucket in us-east-1 must not carry a LocationConstraint; every other region must.
    create_kwargs: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:check", "Value": CHECK},
            ]
        },
    )

    keys = {
        _BUSY_ID: ("busy/probe-object", _BUSY_BODY),
        _QUIET_ID: ("quiet/probe-object", _QUIET_BODY),
        _SILENT_ID: ("silent/probe-object", _SILENT_BODY),
    }
    for _config_id, (key, body) in keys.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body)

    for config_id, prefix in _CONFIGS.items():
        s3.put_bucket_metrics_configuration(
            Bucket=bucket,
            Id=config_id,
            MetricsConfiguration={"Id": config_id, "Filter": {"Prefix": prefix}},
        )
        ctx.on_cleanup(
            lambda cid=config_id: ctx.client("s3").delete_bucket_metrics_configuration(
                Bucket=bucket, Id=cid
            )
        )

    # The configurations must read back with their prefixes intact, or every attribution below is
    # against the wrong filter.
    for config_id, prefix in _CONFIGS.items():
        stored = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=config_id)[
            "MetricsConfiguration"
        ]
        assert stored["Id"] == config_id, (
            f"metrics configuration read back Id {stored['Id']!r}, expected {config_id!r}"
        )
        assert stored["Filter"]["Prefix"] == prefix, (
            f"metrics configuration {config_id!r} read back prefix "
            f"{stored['Filter'].get('Prefix')!r}, expected {prefix!r} -- the prefix IS the "
            f"partition this check measures"
        )

    def _drive_traffic() -> None:
        """One pass of the 6:1:0 ratio, plus one guaranteed 404 under the busy prefix."""
        for _ in range(_BUSY_GETS_PER_PASS):
            s3.get_object(Bucket=bucket, Key=keys[_BUSY_ID][0])["Body"].read()
        for _ in range(_QUIET_GETS_PER_PASS):
            s3.get_object(Bucket=bucket, Key=keys[_QUIET_ID][0])["Body"].read()
        # A 404 under busy/ only. Scoped to NoSuchKey so a permissions or networking failure still
        # surfaces as an error rather than being swallowed as "the 404 we wanted".
        try:
            s3.get_object(Bucket=bucket, Key="busy/deliberately-absent-object")
        except s3.exceptions.NoSuchKey:
            pass
        # silent/ is never read. That absence is the structural control.

    def _sum_of(metric: str, config_id: str) -> float | None:
        """Sum of *metric* for one filter over the whole run window, or None if no datapoint yet."""
        datapoints = _statistics(cw, bucket, config_id, metric, ["Sum"])
        if not datapoints:
            return None
        return sum(float(dp["Sum"]) for dp in datapoints)

    def _probe() -> tuple[float | None, float | None, list[dict]]:
        return (
            _sum_of("GetRequests", _BUSY_ID),
            _sum_of("GetRequests", _QUIET_ID),
            _list_bucket_metrics(cw, bucket),
        )

    def _ready(probe: tuple[float | None, float | None, list[dict]]) -> bool:
        busy, quiet, listed = probe
        if busy is None or quiet is None:
            return False
        seen = {
            d["Value"] for metric in listed for d in metric["Dimensions"] if d["Name"] != "BucketName"
        }
        return {_BUSY_ID, _QUIET_ID} <= seen

    last_drive = [time.monotonic()]

    def _redrive() -> None:
        if time.monotonic() - last_drive[0] >= _DRIVE_EVERY_S:
            _drive_traffic()
            last_drive[0] = time.monotonic()

    _drive_traffic()
    busy_gets, quiet_gets, listed = _poll_until(
        _probe,
        _ready,
        timeout_s=_budget_s(ctx, 1500.0),
        interval_s=_POLL_S, ctx=ctx,
        description=(
            f"AWS/S3 GetRequests datapoints appeared for BOTH the {_BUSY_ID!r} and {_QUIET_ID!r} "
            f"filters on bucket {bucket!r} AND ListMetrics indexed both filters' dimension "
            f"values. There is no API that reports when a metrics configuration has finished "
            f"being enabled (the S3 FAQ says up to 15 minutes), and a first replay against real "
            f"AWS showed the ListMetrics INDEX lagging the datapoint store by MORE than the "
            f"datapoints themselves lag behind the request that produced them -- a filter with "
            f"data already in GetMetricStatistics can still be absent from ListMetrics -- so "
            f"traffic is re-driven each minute and the index is re-polled until both agree. An "
            f"exhausted poll here is a FAIL, and if it is a BUDGET failure rather than a fidelity "
            f"one, see the blessing note at the top of this file"
        ),
        on_iteration=_redrive,
    )

    # The dimension values are server-derived from the configurations just created. `listed` is
    # the poll result that satisfied `_ready`: ListMetrics lags on its own, so a re-query could
    # regress.
    assert listed, (
        f"ListMetrics found no AWS/S3 metrics dimensioned on BucketName={bucket!r} even though "
        f"GetMetricStatistics returned datapoints for two filters; the metric index and the "
        f"datapoint store disagree"
    )
    filter_dimension_names = {
        d["Name"] for metric in listed for d in metric["Dimensions"] if d["Name"] != "BucketName"
    }
    assert filter_dimension_names, (
        f"every AWS/S3 metric on this bucket is dimensioned on BucketName ALONE "
        f"({listed!r}); three metrics configurations exist, so a second dimension must "
        f"distinguish them or the filters are not being applied at all"
    )
    # Isolated so a wrong dimension name fails only here; the name-free claims below still grade.
    assert filter_dimension_names == {"FilterId"}, (
        f"the dimension distinguishing the metrics configurations is named "
        f"{sorted(filter_dimension_names)!r}, expected exactly ['FilterId']"
    )
    seen_ids = {
        d["Value"]
        for metric in listed
        for d in metric["Dimensions"]
        if d["Name"] != "BucketName"
    }
    assert {_BUSY_ID, _QUIET_ID} <= seen_ids, (
        f"the filters carrying traffic are missing from the metric index: found dimension values "
        f"{sorted(seen_ids)!r}, expected at least {sorted({_BUSY_ID, _QUIET_ID})!r}"
    )
    assert seen_ids <= set(_CONFIGS), (
        f"the metric index reports filter dimension values {sorted(seen_ids)!r}, which include "
        f"identifiers this check never created; the only configurations on {bucket!r} are "
        f"{sorted(_CONFIGS)!r}"
    )

    # The filter partitions by prefix.
    busy_gets = _sum_of("GetRequests", _BUSY_ID)
    quiet_gets = _sum_of("GetRequests", _QUIET_ID)
    assert busy_gets is not None and quiet_gets is not None, (
        f"GetRequests vanished between the poll and the assertion: busy={busy_gets!r} "
        f"quiet={quiet_gets!r}"
    )
    assert busy_gets > quiet_gets, (
        f"the busy prefix reports GetRequests Sum {busy_gets!r} and the quiet prefix "
        f"{quiet_gets!r}; traffic was driven at {_BUSY_GETS_PER_PASS}:{_QUIET_GETS_PER_PASS} on "
        f"EVERY traffic pass, so busy must be strictly larger. Equal values are the signature of a "
        f"single bucket-wide series being reported under both FilterIds -- i.e. the prefix filter "
        f"stored and ignored. No exact count is asserted because CloudWatch delivers these "
        f"metrics on a best-effort basis"
    )

    # A populated prefix nobody read has no GetRequests datapoints.
    silent_datapoints = _statistics(cw, bucket, _SILENT_ID, "GetRequests", ["Sum", "SampleCount"])
    assert silent_datapoints == [], (
        f"the {_SILENT_ID!r} filter reports GetRequests datapoints {silent_datapoints!r}. No "
        f"GetObject was ever issued under its prefix {_CONFIGS[_SILENT_ID]!r} -- only the one PUT "
        f"that populated it -- so a GetRequests datapoint means requests are being attributed to "
        f"the wrong filter. Best-effort delivery cannot explain this away: loss only ever REMOVES "
        f"datapoints, so it can never create the ones asserted absent here"
    )

    # Units are fixed by the documentation.
    busy_datapoints = _statistics(cw, bucket, _BUSY_ID, "GetRequests", ["Sum"])
    assert busy_datapoints, f"GetRequests for {_BUSY_ID!r} returned no datapoints"
    for datapoint in busy_datapoints:
        assert datapoint["Unit"] == "Count", (
            f"a GetRequests datapoint reports Unit {datapoint['Unit']!r}, expected 'Count' -- the "
            f"S3 metrics reference fixes the unit of every request-count metric"
        )

    downloaded = _statistics(cw, bucket, _BUSY_ID, "BytesDownloaded", ["Sum"])
    assert downloaded, (
        f"the {_BUSY_ID!r} filter served {_BUSY_GETS_PER_PASS} GetObject calls per pass with a "
        f"{len(_BUSY_BODY)}-byte body and reports no BytesDownloaded datapoints at all"
    )
    for datapoint in downloaded:
        assert datapoint["Unit"] == "Bytes", (
            f"a BytesDownloaded datapoint reports Unit {datapoint['Unit']!r}, expected 'Bytes'"
        )
    downloaded_sum = sum(float(dp["Sum"]) for dp in downloaded)
    assert downloaded_sum >= float(len(_BUSY_BODY)), (
        f"BytesDownloaded for the busy prefix totals {downloaded_sum!r}, which is less than the "
        f"{len(_BUSY_BODY)} bytes of ONE object. At least one GET demonstrably succeeded (its "
        f"GetRequests datapoint exists), so a single object's payload is a floor best-effort "
        f"delivery cannot excuse falling below"
    )

    # The filter partitions by outcome class too. An active filter gets a 4xxErrors datapoint with
    # Sum 0.0 even when nothing failed, so the SUM, not the presence of datapoints, is asserted.
    busy_4xx = _statistics(cw, bucket, _BUSY_ID, "4xxErrors", ["Sum"])
    assert busy_4xx, (
        f"the busy prefix received a GetObject for a key that does not exist on every traffic pass, "
        f"so the {_BUSY_ID!r} filter must report 4xxErrors; got no datapoints"
    )
    for datapoint in busy_4xx:
        assert datapoint["Unit"] == "Count", (
            f"a 4xxErrors datapoint reports Unit {datapoint['Unit']!r}, expected 'Count'"
        )
    busy_4xx_sum = sum(float(dp["Sum"]) for dp in busy_4xx)
    assert busy_4xx_sum > 0, (
        f"the busy prefix received a GetObject for a key that does not exist on every traffic pass, "
        f"so the {_BUSY_ID!r} filter's 4xxErrors must sum to more than zero; got datapoints "
        f"{busy_4xx!r} summing to {busy_4xx_sum!r} -- present-but-zero is what an ACTIVE filter "
        f"with no errors looks like, which is not this filter"
    )
    quiet_4xx = _statistics(cw, bucket, _QUIET_ID, "4xxErrors", ["Sum"])
    quiet_4xx_sum = sum(float(dp["Sum"]) for dp in quiet_4xx)
    assert quiet_4xx_sum == 0.0, (
        f"the {_QUIET_ID!r} filter reports 4xxErrors summing to {quiet_4xx_sum!r} across "
        f"datapoints {quiet_4xx!r}; every request under its prefix was a successful GET of an "
        f"object that exists, and the 404s were issued under {_CONFIGS[_BUSY_ID]!r}. This is what "
        f"proves the partition is by prefix rather than the bucket's errors being fanned out to "
        f"every filter"
    )

    # Terminal read at the consumer, through a different operation.
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)
    results = cw.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "busy",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/S3",
                        "MetricName": "GetRequests",
                        "Dimensions": [
                            {"Name": "BucketName", "Value": bucket},
                            {"Name": "FilterId", "Value": _BUSY_ID},
                        ],
                    },
                    "Period": 60,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            }
        ],
        StartTime=start,
        EndTime=end,
        ScanBy="TimestampAscending",
    )["MetricDataResults"]
    assert len(results) == 1, (
        f"GetMetricData for one AWS/S3 series returned {len(results)} results {results!r}, "
        f"expected 1"
    )
    values = [float(v) for v in results[0]["Values"]]
    assert values, (
        f"GetMetricData returned no values for the busy filter although GetMetricStatistics "
        f"reported Sum {busy_gets!r} over the same window; the two read paths disagree about the "
        f"same series"
    )
    assert sum(values) >= 1.0, (
        f"GetMetricData totals {sum(values)!r} for a series GetMetricStatistics reported as "
        f"{busy_gets!r}; a positive Sum on one read path and nothing on the other means the metric "
        f"is not stored once and projected twice"
    )


def _statistics(cw, bucket: str, config_id: str, metric: str, statistics: list[str]) -> list[dict]:
    """GetMetricStatistics for one AWS/S3 request metric scoped to one metrics configuration.

    The window reaches well back: S3 may stamp a datapoint later than the request it describes.
    """
    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    start = end - timedelta(hours=2)
    return cw.get_metric_statistics(
        Namespace="AWS/S3",
        MetricName=metric,
        Dimensions=[
            {"Name": "BucketName", "Value": bucket},
            {"Name": "FilterId", "Value": config_id},
        ],
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=statistics,
    )["Datapoints"]


def _list_bucket_metrics(cw, bucket: str) -> list[dict]:
    """Every AWS/S3 metric the index holds for this bucket, paginated."""
    out = []
    for page in cw.get_paginator("list_metrics").paginate(
        Namespace="AWS/S3", Dimensions=[{"Name": "BucketName", "Value": bucket}]
    ):
        out.extend(page["Metrics"])
    return out


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Delete every object (and version) in this check's bucket, then the bucket."""
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        entries = [
            {"Key": item["Key"], "VersionId": item["VersionId"]}
            for group in ("Versions", "DeleteMarkers")
            for item in page.get(group, [])
        ]
        if entries:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": entries})
    s3.delete_bucket(Bucket=bucket)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None,
                ctx=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
