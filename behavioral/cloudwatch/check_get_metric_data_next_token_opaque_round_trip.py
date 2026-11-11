"""get-metric-data-next-token-opaque-round-trip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-next-token-opaque-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GetMetricData NextToken, replayed verbatim, deterministically returns the same next page."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-paginate-")
    metric_name = ctx.unique_name("PaginatedMetric-")
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # Five historical, distinct one-minute-apart datapoints so a single query spans
    # multiple periods and can be forced to paginate with a small MaxDatapoints.
    offsets = [5, 4, 3, 2, 1]
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now - timedelta(minutes=m),
                "Value": float(m),
                "Unit": "None",
            }
            for m in offsets
        ],
    )

    query = [
        {
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_name},
                "Period": 60,
                "Stat": "Average",
            },
            "ReturnData": True,
        }
    ]
    start_time = now - timedelta(minutes=6)
    end_time = now + timedelta(minutes=1)

    # Wait until all five datapoints are visible before exercising pagination.
    _poll_until(
        lambda: cw.get_metric_data(MetricDataQueries=query, StartTime=start_time, EndTime=end_time),
        lambda r: len(r["MetricDataResults"][0]["Values"]) >= 5,
        timeout_s=180.0,
        interval_s=10.0,
        description="all 5 historical datapoints visible",
    )

    page1 = cw.get_metric_data(
        MetricDataQueries=query, StartTime=start_time, EndTime=end_time, MaxDatapoints=1
    )
    next_token = page1.get("NextToken")
    assert next_token, "expected a NextToken when MaxDatapoints=1 caps a 5-datapoint result"
    page1_stamps = page1["MetricDataResults"][0]["Timestamps"]

    page2a = cw.get_metric_data(
        MetricDataQueries=query, StartTime=start_time, EndTime=end_time, MaxDatapoints=1, NextToken=next_token
    )
    page2b = cw.get_metric_data(
        MetricDataQueries=query, StartTime=start_time, EndTime=end_time, MaxDatapoints=1, NextToken=next_token
    )

    page2a_stamps = page2a["MetricDataResults"][0]["Timestamps"]
    page2a_values = page2a["MetricDataResults"][0]["Values"]
    page2b_stamps = page2b["MetricDataResults"][0]["Timestamps"]
    page2b_values = page2b["MetricDataResults"][0]["Values"]

    # Replaying the exact same token twice must deterministically return the same page.
    assert page2a_stamps == page2b_stamps, f"replaying NextToken gave different timestamps: {page2a_stamps} vs {page2b_stamps}"
    assert page2a_values == page2b_values, f"replaying NextToken gave different values: {page2a_values} vs {page2b_values}"

    # The second page must actually be the NEXT page, not a repeat of page 1.
    assert page2a_stamps != page1_stamps, "NextToken did not advance past page 1's data"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
