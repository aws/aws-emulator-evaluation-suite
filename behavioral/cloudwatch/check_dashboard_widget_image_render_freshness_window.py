"""dashboard-widget-image-render-freshness-window."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "dashboard-widget-image-render-freshness-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage over a fixed absolute window returns a PNG, the same bytes again over
    unchanged data, and different bytes once a new datapoint is written into the window: the
    render reads current data, not a cached image."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-widget-")
    metric_name = "widget-freshness-metric"

    now = datetime.now(timezone.utc).replace(microsecond=0)
    window_start = now - timedelta(minutes=5)
    window_end = now + timedelta(minutes=5)
    fmt = "%Y-%m-%dT%H:%M:%SZ"

    def widget_json() -> str:
        return json.dumps(
            {
                "metrics": [[namespace, metric_name, {"stat": "Sum", "period": 60}]],
                "start": window_start.strftime(fmt),
                "end": window_end.strftime(fmt),
                "width": 400,
                "height": 300,
                "view": "timeSeries",
            }
        )

    def window_sum() -> float:
        dps = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, StartTime=window_start,
            EndTime=window_end, Period=60, Statistics=["Sum"],
        )["Datapoints"]
        return sum(d["Sum"] for d in dps)

    # Each render follows a read that shows the write ingested, so both renders of a pair see the
    # same data and the change in bytes is attributable to the second write.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 1.0}],
    )
    _poll_until(window_sum, lambda total: total == 1.0, timeout_s=90, interval_s=3)
    image_before = cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"]
    assert image_before[:8] == _PNG_MAGIC, "GetMetricWidgetImage did not return a PNG"

    image_before_repeat = cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"]
    assert image_before_repeat == image_before, (
        "the identical widget spec over unchanged data rendered differently on a second call -- "
        "the render is not a pure function of the spec, so a later change in bytes cannot be "
        "attributed to the metric write"
    )

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 500.0}],
    )
    _poll_until(window_sum, lambda total: total == 501.0, timeout_s=90, interval_s=3)

    image_after = _poll_until(
        lambda: cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"],
        lambda img: img != image_before,
        timeout_s=90,
        interval_s=5,
    )
    assert image_after[:8] == _PNG_MAGIC, "GetMetricWidgetImage did not return a PNG after the second write"
    assert image_after != image_before, "widget render never reflected the new metric datapoint"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    shown = f"{len(last)} bytes" if isinstance(last, bytes) else repr(last)
    raise AssertionError(f"condition not met within {timeout_s}s (last observation {shown})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
