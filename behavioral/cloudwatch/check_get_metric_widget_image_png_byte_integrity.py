"""get-metric-widget-image-png-byte-integrity."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-metric-widget-image-png-byte-integrity"
GROUP = "representation"
SERVICES = ["cloudwatch"]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage returns a structurally valid, byte-stable PNG for a fixed
    absolute-time-range widget definition across repeated identical requests -- not a
    placeholder, a truncated stream, or a re-rendered-with-noise image."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-")
    widget = {
        "title": "sim2real byte-integrity widget",
        "view": "timeSeries",
        "width": 400,
        "height": 300,
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-01T01:00:00Z",
        # deliberately references a metric that has never had data published, so the
        # rendered chart (axes + empty series, no live "now" marker) is fully
        # deterministic across repeated calls.
        "metrics": [[namespace, "NoSuchMetricEver"]],
    }
    widget_json = json.dumps(widget)

    image1 = _get_image_bytes(cw, widget_json)
    image2 = _get_image_bytes(cw, widget_json)

    assert image1[:8] == _PNG_MAGIC, f"not a PNG: first bytes {image1[:8]!r}"
    assert len(image1) > 500, f"suspiciously small image: {len(image1)} bytes"
    assert b"IHDR" in image1[:64], "missing PNG IHDR chunk near header"
    assert image1 == image2, "identical widget request produced a different image on repeat"

    # A canned placeholder PNG would pass every assertion above unchanged, since it never varies
    # with the request. Decode the IHDR dimensions and hold them to the requested width/height, so
    # a target that returns a fixed image regardless of the spec fails here instead.
    ihdr_width, ihdr_height = _png_dimensions(image1)
    assert (ihdr_width, ihdr_height) == (widget["width"], widget["height"]), (
        f"rendered PNG dims {(ihdr_width, ihdr_height)} != requested "
        f"{(widget['width'], widget['height'])}"
    )


def _get_image_bytes(cw, widget_json: str) -> bytes:
    resp = cw.get_metric_widget_image(MetricWidget=widget_json, OutputFormat="png")
    blob = resp["MetricWidgetImage"]
    return blob.read() if hasattr(blob, "read") else blob


def _png_dimensions(data: bytes) -> tuple[int, int]:
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
