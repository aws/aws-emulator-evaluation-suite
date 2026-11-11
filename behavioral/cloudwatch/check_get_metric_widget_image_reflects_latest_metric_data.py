"""get-metric-widget-image-reflects-latest-metric-data."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-widget-image-reflects-latest-metric-data"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage re-renders from live metric data rather than serving a cached image:
    the same widget spec (identical, fixed time window) produces a different PNG once new data
    has been published for the metric it graphs."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cwimg-ns-")
    metric_name = "WidgetMetric"

    # Fix the widget's time window as absolute timestamps computed once, so the two renders use
    # an identical window and any pixel difference is attributable to the metric data, not to a
    # naturally-advancing "now".
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start_iso = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    widget = {
        "metrics": [[namespace, metric_name, {"stat": "Maximum"}]],
        "start": start_iso,
        "end": end_iso,
        "period": 60,
        "width": 400,
        "height": 300,
        "view": "timeSeries",
    }
    widget_json = json.dumps(widget)

    def _render() -> bytes:
        return cw.get_metric_widget_image(MetricWidget=widget_json)["MetricWidgetImage"]

    image_before = _render()
    assert image_before[:8] == _PNG_MAGIC, "GetMetricWidgetImage did not return a PNG"

    # Freeze detector: the window's end sits a few minutes into the future, so an immediate
    # re-render of the identical spec -- before any new data exists -- must still be byte-identical.
    # Without this control, a later "image changed" signal could be a live now-marker or non-
    # deterministic rendering rather than an effect of the metric data we are about to publish.
    image_before_repeat = _render()
    assert image_before_repeat == image_before, (
        "widget image changed on a repeat render with no new data and an unchanged spec "
        "(baseline is not stable, so a later change cannot be attributed to new metric data)"
    )

    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 987654.0}])

    image_after = _poll_until_image_changes(_render, image_before, timeout_s=60, interval_s=5)
    assert image_after is not None, "widget image never changed after publishing new metric data"
    assert image_after[:8] == _PNG_MAGIC, "re-rendered GetMetricWidgetImage output is not a PNG"
    assert image_after != image_before, "widget image identical before/after new data (looks cached, not re-rendered)"


def _poll_until_image_changes(render_fn, baseline: bytes, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        candidate = render_fn()
        if candidate != baseline:
            return candidate
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
