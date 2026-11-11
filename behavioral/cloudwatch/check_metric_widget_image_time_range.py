"""metric-widget-image-time-range."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-widget-image-time-range"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage renders only the metric data points falling within
    the specified time range: widening the range to include an earlier spike,
    or narrowing it to a range with no data at all, must change the image.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "SpikeMetric"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Timestamp": now - timedelta(hours=2), "Value": 1000.0},
            {"MetricName": metric_name, "Timestamp": now - timedelta(minutes=1), "Value": 1.0},
        ],
    )

    def probe():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(hours=3),
            EndTime=now + timedelta(minutes=5),
            Period=60,
            Statistics=["Maximum"],
        )
        return resp.get("Datapoints", [])

    _poll_until(
        probe, lambda dps: len(dps) >= 2, timeout_s=60, interval_s=3, description="both datapoints ingested"
    )

    def widget_image(start_iso, end_iso):
        widget = json.dumps(
            {
                "metrics": [[namespace, metric_name, {"stat": "Maximum", "period": 60}]],
                "view": "timeSeries",
                "start": start_iso,
                "end": end_iso,
                "width": 400,
                "height": 200,
            }
        )
        resp = cw.get_metric_widget_image(MetricWidget=widget)
        return resp["MetricWidgetImage"]

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    narrow = widget_image((now - timedelta(minutes=10)).strftime(fmt), now.strftime(fmt))
    wide = widget_image((now - timedelta(hours=3)).strftime(fmt), now.strftime(fmt))
    empty = widget_image((now - timedelta(days=365)).strftime(fmt), (now - timedelta(days=300)).strftime(fmt))

    for img in (narrow, wide, empty):
        assert isinstance(img, (bytes, bytearray)) and img[:8] == b"\x89PNG\r\n\x1a\n", (
            "expected GetMetricWidgetImage to return a valid PNG image"
        )

    assert wide != narrow, (
        "widening the time range to include the earlier spike must change the rendered image"
    )
    assert empty != narrow and empty != wide, (
        "a time range containing no data points at all must render differently from ranges that do"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
