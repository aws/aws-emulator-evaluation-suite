"""get-metric-widget-image-server-rendering."""
from __future__ import annotations

import base64
import json
import struct
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-widget-image-server-rendering"
GROUP = "server-side"
SERVICES = ["cloudwatch"]

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _decode(image_bytes) -> bytes:
    if hasattr(image_bytes, "read"):
        image_bytes = image_bytes.read()
    if isinstance(image_bytes, str):
        image_bytes = base64.b64decode(image_bytes)
    return bytes(image_bytes)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage renders a PNG whose encoded dimensions match the MetricWidget spec, and
    the render is a function of the published metric data, not a static placeholder image.
    """
    cw = ctx.client("cloudwatch")
    # No ctx.on_cleanup: CloudWatch has no DeleteMetric/DeleteNamespace API, so published metric
    # data is a permanent (free) mark on the account with nothing to tear down.
    namespace = ctx.unique_name("Sim2RealBehavWidgetNS")
    metric_name = "WidgetMetric"

    # Absolute start/end computed once: a relative "-PT1H"/"PT0H" window slides between the two
    # renders below and would make "same spec, different bytes" ambiguous between "data changed
    # the render" and "the window itself moved". The end boundary sits 5 minutes past "now" so
    # the datapoint published at "now" falls comfortably inside the window rather than landing
    # exactly on its edge, where it is liable to be excluded.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start_iso = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    width, height = 480, 320
    widget = {
        "metrics": [[namespace, metric_name, {"stat": "Sum"}]],
        "width": width,
        "height": height,
        "period": 60,
        "start": start_iso,
        "end": end_iso,
        "title": "sim2real-behav-widget",
    }
    widget_json = json.dumps(widget)

    def _render() -> bytes:
        resp = cw.get_metric_widget_image(MetricWidget=widget_json, OutputFormat="png")
        return _decode(resp["MetricWidgetImage"])

    empty_bytes = _render()
    assert empty_bytes[:8] == _PNG_SIGNATURE, "GetMetricWidgetImage did not return a valid PNG"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 42.0, "Unit": "Count"}],
    )

    # Bounded retry: metric data takes a few seconds to become queryable, and a target that
    # ignores the data entirely (a static or cached placeholder) must never be mistaken for one
    # that is still catching up.
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    image_bytes = None
    while time.monotonic() < deadline:
        candidate = _render()
        if candidate != empty_bytes:
            image_bytes = candidate
            break
        time.sleep(2)
    if image_bytes is None:
        raise AssertionError(
            "GetMetricWidgetImage returned byte-identical images before and after publishing "
            "metric data -- the render does not reflect what was just published"
        )

    assert image_bytes[:8] == _PNG_SIGNATURE, "GetMetricWidgetImage did not return a valid PNG"
    # PNG IHDR chunk: [4-byte length]["IHDR"][4-byte width][4-byte height] starting at offset 8.
    chunk_type = image_bytes[12:16]
    assert chunk_type == b"IHDR", f"expected IHDR as the first chunk, got {chunk_type!r}"
    ihdr_width, ihdr_height = struct.unpack(">II", image_bytes[16:24])
    assert ihdr_width == width, f"expected rendered width {width}, got {ihdr_width}"
    assert ihdr_height == height, f"expected rendered height {height}, got {ihdr_height}"
    assert len(image_bytes) > 500, "rendered image is suspiciously small for a real chart"

    # Re-rendering the identical spec over the now-unchanging series must be byte-identical: a
    # renderer whose output is not a function of its inputs cannot be graded, and a stub emitting
    # fresh random noise on every call would otherwise pass the "differs from empty" leg above.
    again_bytes = _render()
    assert again_bytes == image_bytes, (
        f"re-rendering the same spec over the same data produced a different image "
        f"({len(image_bytes)} vs {len(again_bytes)} bytes) -- the renderer is not deterministic "
        f"in its own inputs"
    )

    # A differently-sized request still renders, at the requested size.
    widget_small = dict(widget, width=200, height=100)
    resp_small = cw.get_metric_widget_image(MetricWidget=json.dumps(widget_small), OutputFormat="png")
    small_bytes = _decode(resp_small["MetricWidgetImage"])
    small_w, small_h = struct.unpack(">II", small_bytes[16:24])
    assert (small_w, small_h) == (200, 100), f"expected (200, 100), got {(small_w, small_h)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
