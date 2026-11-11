"""get-metric-widget-image-png-byte-equality-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-metric-widget-image-png-byte-equality-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two GetMetricWidgetImage calls with an identical widget spec (a fixed past window, a metric with
    no data) return byte-identical PNGs whose IHDR width/height equal the requested 400x200, so a
    canned placeholder image cannot pass."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    width, height = 400, 200
    widget = (
        '{"metrics":[["%s","NoSuchMetric"]],'
        '"start":"2023-01-01T00:00:00Z","end":"2023-01-01T01:00:00Z",'
        '"period":300,"stat":"Average","width":%d,"height":%d,"title":"fixed-window"}'
    ) % (namespace, width, height)

    image1 = bytes(cw.get_metric_widget_image(MetricWidget=widget, OutputFormat="png")["MetricWidgetImage"])
    image2 = bytes(cw.get_metric_widget_image(MetricWidget=widget, OutputFormat="png")["MetricWidgetImage"])

    assert image1[:8] == _PNG_MAGIC, "response is not a valid PNG"
    assert image2[:8] == _PNG_MAGIC, "response is not a valid PNG"
    assert len(image1) > 500, f"suspiciously small image: {len(image1)} bytes"
    assert b"IHDR" in image1[:64], "missing PNG IHDR chunk near header"
    assert image1 == image2, "identical widget spec produced different image bytes"

    # A canned placeholder PNG would pass every assertion above unchanged, since it never
    # varies with the request. Decode the IHDR dimensions and hold them to the requested
    # width/height, so a target that returns a fixed image regardless of the spec fails here.
    ihdr_width, ihdr_height = _png_dimensions(image1)
    assert (ihdr_width, ihdr_height) == (width, height), (
        f"rendered PNG dims {(ihdr_width, ihdr_height)} != requested {(width, height)}"
    )


def _png_dimensions(data: bytes) -> tuple[int, int]:
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
