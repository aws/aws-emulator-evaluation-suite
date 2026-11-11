"""get-metric-widget-image-valid-spec-renders."""
from __future__ import annotations

import json
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "get-metric-widget-image-valid-spec-renders"
GROUP = "server-side"
SERVICES = ["cloudwatch"]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A valid MetricWidget spec renders a PNG whose IHDR carries the requested width/height,
    whose bytes change once data is published for the graphed metric, and which re-renders
    byte-identically over unchanged data."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavWidget")
    metric_name = "Throughput"
    width, height = 400, 300

    # An absolute window: a relative "-PT1H" window slides between renders.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=20)
    end = now + timedelta(minutes=5)

    def widget_json() -> str:
        return json.dumps(
            {
                "metrics": [[namespace, metric_name, {"stat": "Average"}]],
                "period": 60,
                "width": width,
                "height": height,
                "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )

    def _render() -> bytes:
        resp = cw.get_metric_widget_image(MetricWidget=widget_json(), OutputFormat="png")
        image = resp["MetricWidgetImage"]
        return image.read() if hasattr(image, "read") else bytes(image)

    empty_png = _render()
    _assert_valid_png(empty_png, width, height, "pre-publish (empty)")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Value": 42.0,
                "Unit": "Count",
            }
        ],
    )

    if not _poll_metric_visible(cw, namespace, metric_name, start, end, timeout_s=90.0, interval_s=5.0):
        raise AssertionError(
            "metric data did not become visible via GetMetricStatistics within the poll window "
            "(CloudWatch ingestion is eventually consistent)",
        )

    full_png = _render()
    _assert_valid_png(full_png, width, height, "post-publish")
    assert full_png != empty_png, (
        "the byte-identical widget spec rendered identically before and after publishing real "
        "metric data -- the renderer ignores the data, which is exactly what a stored "
        "placeholder looks like"
    )

    again_png = _render()
    _assert_valid_png(again_png, width, height, "repeat post-publish")
    assert again_png == full_png, (
        "re-rendering the identical spec over unchanged data produced different bytes -- a "
        "renderer whose output is not a pure function of its inputs cannot be graded, and a "
        "stub emitting noise would pass the differs-from-empty check above"
    )


def _assert_valid_png(data: bytes, width: int, height: int, label: str) -> None:
    assert isinstance(data, bytes) and len(data) > 100, (
        f"{label}: expected a non-trivial rendered PNG payload, got {len(data) if data else 0} bytes"
    )
    assert data[:8] == _PNG_MAGIC, f"{label}: rendered image does not start with PNG magic bytes"
    dims = struct.unpack(">II", data[16:24])
    assert dims == (width, height), f"{label}: IHDR dimensions {dims} != requested {(width, height)}"


def _poll_metric_visible(
    cw: Any, namespace: str, metric_name: str, start: datetime, end: datetime, *, timeout_s: float, interval_s: float
) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Average"],
        )
        if resp.get("Datapoints"):
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
