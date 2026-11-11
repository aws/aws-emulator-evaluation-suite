"""get-metric-widget-image-reflects-published-datapoints."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-widget-image-reflects-published-datapoints"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage renders a PNG that changes once PutMetricData publishes datapoints into
    the metric/time window the widget queries, and re-rendering the same spec over unchanged data
    is byte-for-byte stable (a noise-emitting renderer fails)."""

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-widget-")
    metric_name = "WidgetMetric"

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=20)
    end = now + timedelta(minutes=1)

    def widget_json() -> str:
        return json.dumps(
            {
                "metrics": [[namespace, metric_name, {"stat": "Maximum"}]],
                "view": "timeSeries",
                "stacked": False,
                "period": 60,
                "width": 600,
                "height": 400,
                "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "yAxis": {"left": {"min": 0, "max": 200}},
                "title": "widget-fidelity-check",
            }
        )

    baseline = cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"]
    baseline_len = len(baseline)
    assert baseline_len > 0, "GetMetricWidgetImage returned an empty image for a valid widget spec"
    assert baseline[:8] == b"\x89PNG\r\n\x1a\n", (
        f"GetMetricWidgetImage baseline response is not a PNG: first 8 bytes {baseline[:8]!r}"
    )

    for i in range(5):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": now - timedelta(minutes=i),
                    "Value": 100.0 + i,
                    "Unit": "Count",
                }
            ],
        )

    # The renders below follow a read showing all five datapoints ingested, so the render that is
    # graded and its determinism re-render see the same data.
    left = ctx.time_left()
    deadline = time.monotonic() + (150.0 if left is None else min(150.0, left))
    visible = 0
    while time.monotonic() < deadline:
        visible = len(cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, StartTime=start, EndTime=end,
            Period=60, Statistics=["Maximum"],
        )["Datapoints"])
        if visible >= 5:
            break
        time.sleep(2)
    assert visible >= 5, (
        f"GetMetricStatistics shows {visible} of the 5 published datapoints within the poll timeout"
    )

    # A rendered data line is visually/byte-wise much heavier than an empty chart grid; this
    # threshold distinguishes "data plotted" from watermark/timestamp jitter alone.
    after = None
    while time.monotonic() < deadline:
        image = cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"]
        if len(image) > baseline_len + 200:
            after = image
            break
        time.sleep(2)

    if after is None:
        raise AssertionError(
            "published metric data was not reflected in GetMetricWidgetImage within the poll timeout"
        )

    assert after[:8] == b"\x89PNG\r\n\x1a\n", (
        f"GetMetricWidgetImage response after publishing is not a PNG: first 8 bytes {after[:8]!r}"
    )
    assert after != baseline, "widget image bytes did not change after publishing new datapoints"
    assert len(after) > baseline_len + 200, (
        f"widget image grew only {len(after) - baseline_len} bytes after publishing 5 datapoints, "
        f"expected > 200 (baseline {baseline_len}, after {len(after)})"
    )

    # Determinism leg: the data is now static (no more publishes), so re-rendering the identical
    # spec must reproduce the identical bytes. Without this, a stub that emits fresh random noise
    # on every call would pass the two asserts above (different from baseline, bigger than
    # baseline) without ever having rendered the published data.
    again = cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"]
    assert again == after, (
        f"re-rendering the identical widget spec over unchanged data produced different bytes "
        f"({len(after)} vs {len(again)}) -- a renderer whose output is not a function of its "
        f"inputs cannot be graded, and a noise-emitting stub would pass the differs-from-baseline "
        f"assertion above without ever reflecting the published data"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
