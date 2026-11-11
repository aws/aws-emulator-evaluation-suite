"""e2e-dashboard-with-live-metric-widget-image."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-dashboard-with-live-metric-widget-image"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish metric data -> dashboard widget over it -> render image -> delete -> gone.

    The widget image must differ once data exists (not a stored PNG) and re-render
    byte-identically on unchanged data (not noise); the dashboard 404s after delete.
    """
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2Real/DashboardWidget")
    metric_name = "WidgetValue"
    dashboard_name = ctx.unique_name("sim2real-dash-")

    # An absolute window, fixed before the first render: a relative one slides with the clock, so
    # two renders of the same data a moment apart would differ.
    window_end = datetime.fromtimestamp(int(time.time()), tz=timezone.utc)
    image_widget = {
        "metrics": [[namespace, metric_name, {"stat": "Sum"}]],
        "period": 300,
        "stat": "Sum",
        "width": 400,
        "height": 300,
        "start": (window_end - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Rendered before any data exists in this (uniquely-named) namespace, so a target that
    # returns a fixed/stored PNG regardless of input cannot be told apart from a real renderer
    # by the size+magic-bytes checks alone -- the empty-vs-full comparison below closes that.
    empty_resp = cw.get_metric_widget_image(MetricWidget=json.dumps(image_widget), OutputFormat="png")
    empty_raw = empty_resp["MetricWidgetImage"]
    empty_bytes = empty_raw.read() if hasattr(empty_raw, "read") else empty_raw
    assert empty_bytes[:8] == b"\x89PNG\r\n\x1a\n", (
        f"the pre-data widget image is not a PNG: first 8 bytes {empty_bytes[:8]!r}"
    )

    now = window_end.timestamp()
    t0 = now - 120
    t1 = now - 60
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Value": 100.0, "Unit": "Count", "Timestamp": t0},
            {"MetricName": metric_name, "Value": 200.0, "Unit": "Count", "Timestamp": t1},
        ],
    )

    start_time = now - 300
    end_time = now + 60

    def _stats():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=["Sum"],
        )["Datapoints"]

    try:
        datapoints = _poll_until(
            _stats, lambda d: sum(p["Sum"] for p in d) == 300.0, timeout_s=300, interval_s=10
        )
    except AssertionError:
        raise AssertionError(
            "PutMetricData datapoints never appeared in GetMetricStatistics within 5 "
            "minutes (CloudWatch ingestion latency) -- not a dashboard/widget fidelity signal",
        )
    assert sum(p["Sum"] for p in datapoints) == 300.0, datapoints


    widget_properties = {
        "metrics": [[namespace, metric_name, {"stat": "Sum"}]],
        "period": 300,
        "stat": "Sum",
        "region": ctx.region,
        "title": "sim2real-widget",
        "start": "-PT10M",
        "end": "PT0M",
    }
    dashboard_body = {
        "widgets": [
            {"type": "metric", "x": 0, "y": 0, "width": 6, "height": 6, "properties": widget_properties}
        ]
    }

    put_resp = cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(dashboard_body))
    ctx.on_cleanup(lambda: _delete_dashboard_ignore(cw, dashboard_name))
    error_messages = [
        m for m in put_resp.get("DashboardValidationMessages", []) if "error" in m.get("Message", "").lower()
    ]
    assert error_messages == []

    got = cw.get_dashboard(DashboardName=dashboard_name)
    got_body = json.loads(got["DashboardBody"])
    assert got_body["widgets"][0]["properties"]["metrics"][0][0] == namespace
    assert got_body["widgets"][0]["properties"]["metrics"][0][1] == metric_name

    image_resp = cw.get_metric_widget_image(MetricWidget=json.dumps(image_widget), OutputFormat="png")
    raw_image = image_resp["MetricWidgetImage"]
    image_bytes = raw_image.read() if hasattr(raw_image, "read") else raw_image
    assert len(image_bytes) > 500
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n"
    assert image_bytes != empty_bytes, (
        f"the byte-identical widget spec rendered identically ({len(image_bytes)} bytes) before "
        "and after two datapoints were published -- the renderer ignores the data, which is "
        "exactly what a stored placeholder looks like"
    )

    again_resp = cw.get_metric_widget_image(MetricWidget=json.dumps(image_widget), OutputFormat="png")
    again_raw = again_resp["MetricWidgetImage"]
    again_bytes = again_raw.read() if hasattr(again_raw, "read") else again_raw
    assert again_bytes == image_bytes, (
        f"re-rendering the same spec over the same data produced a different image "
        f"({len(image_bytes)} vs {len(again_bytes)} bytes) -- a renderer whose output is not a "
        "function of its inputs cannot be graded, and a stub emitting noise would pass the "
        "differs-from-empty check above"
    )

    cw.delete_dashboards(DashboardNames=[dashboard_name])

    def _code_after_delete():
        return _error_code(lambda: cw.get_dashboard(DashboardName=dashboard_name))

    code = _poll_until(_code_after_delete, lambda c: c == "ResourceNotFound", timeout_s=20)
    assert code == "ResourceNotFound"


# ===== helpers =====


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last={last!r}")


def _delete_dashboard_ignore(cw, name):
    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
