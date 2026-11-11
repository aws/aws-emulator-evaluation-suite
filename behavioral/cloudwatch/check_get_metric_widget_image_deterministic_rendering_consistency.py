"""get-metric-widget-image-deterministic-rendering-consistency."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-metric-widget-image-deterministic-rendering-consistency"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identical MetricWidget spec over a fixed, already-elapsed window renders a PNG of the
    requested width/height, byte-identical across calls, so size comes from the spec and the
    render is a pure function of spec and data."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-widget-")
    metric_name = "WidgetConsistencyMetric"

    # A fixed, already-elapsed window so repeated renders query identical data.
    now = time.time()
    start_dt = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600))
    end_dt = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 1800))
    point_ts = time.gmtime(now - 3300)

    point_ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", point_ts)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": point_ts_str,
                "Value": 42.0,
                "Unit": "Count",
            }
        ],
    )

    # Ingestion is eventually consistent; rendering before the datapoint is visible would race
    # ingestion and look like nondeterminism.
    _wait_for_datapoint(cw, namespace, metric_name, start_dt, end_dt)

    width, height = 611, 407  # deliberately non-default so a hardcoded size would fail
    widget = {
        "metrics": [[namespace, metric_name, {"stat": "Sum"}]],
        "view": "timeSeries",
        "width": width,
        "height": height,
        "start": start_dt,
        "end": end_dt,
        "period": 300,
        "title": "consistency-check",
    }
    widget_json = json.dumps(widget)

    images = []
    dims = []
    for _ in range(2):
        image = cw.get_metric_widget_image(MetricWidget=widget_json, OutputFormat="png")["MetricWidgetImage"]
        image_bytes = image.read() if hasattr(image, "read") else bytes(image)
        assert len(image_bytes) > 1024, "rendered image implausibly small to be a real PNG chart"
        images.append(image_bytes)
        dims.append(_png_dimensions(image_bytes))
        time.sleep(2)

    assert dims[0] == (width, height), f"first render dims {dims[0]} != requested ({width}, {height})"
    assert dims[1] == (width, height), f"second render dims {dims[1]} != requested ({width}, {height})"
    assert images[0] == images[1], (
        "repeated calls with an identical spec over an identical, already-elapsed time window "
        "against unchanged (and already-visible) data produced different image bytes -- "
        "rendering is not deterministic"
    )


def _wait_for_datapoint(cw, namespace: str, metric_name: str, start_dt: str, end_dt: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_dt,
            EndTime=end_dt,
            Period=300,
            Statistics=["Sum"],
        )
        if resp.get("Datapoints"):
            return
        time.sleep(3)
    raise AssertionError("published datapoint never became visible via GetMetricStatistics within 60s")


def _png_dimensions(data: bytes) -> tuple[int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "response is not a PNG image"
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
