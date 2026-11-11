"""list-insights-metric-data-shape."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-insights-metric-data-shape"
GROUP = 'insights'
SERVICES = ['cloudtrail']


@tags("axis:happy-path", "cap:c2", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInsightsMetricData with Period 60 and DataType FillWithZeros over a 600 s window echoes EventSource,
    EventName and InsightType and returns exactly 10 Timestamps and 10 Values, Timestamps ascending."""
    ct = ctx.client("cloudtrail")
    period = 60
    window_s = 600
    end_time = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = end_time - timedelta(seconds=window_s)
    resp = ct.list_insights_metric_data(
        EventSource="s3.amazonaws.com",
        EventName="PutObject",
        InsightType="ApiCallRateInsight",
        StartTime=start_time,
        EndTime=end_time,
        Period=period,
        DataType="FillWithZeros",
    )
    assert resp["EventSource"] == "s3.amazonaws.com", resp
    assert resp["EventName"] == "PutObject", resp
    assert resp["InsightType"] == "ApiCallRateInsight", resp

    timestamps = resp["Timestamps"]
    values = resp["Values"]
    assert isinstance(timestamps, list) and isinstance(values, list), resp

    expected = window_s // period
    assert len(timestamps) == expected, (
        f"expected {expected} FillWithZeros datapoints over a {window_s}s/{period}s "
        f"window, got {len(timestamps)}: {timestamps}"
    )
    assert len(values) == expected, (
        f"Values length {len(values)} != expected Timestamps length {expected}: {values}"
    )
    assert timestamps == sorted(timestamps), f"Timestamps are not ascending: {timestamps}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
