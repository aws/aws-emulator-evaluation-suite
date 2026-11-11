"""get-metric-widget-image-returns-valid-png."""
from __future__ import annotations

import json
import struct

from behavioral_harness import tags

CHECK = "get-metric-widget-image-returns-valid-png"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage renders a metric widget definition into an actual PNG image
    (checked via the PNG magic bytes and the encoded IHDR width/height matching the
    requested widget size), not an empty payload or a fixed-size placeholder."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    width, height = 400, 200
    widget = {
        "metrics": [[namespace, "WidgetMetric"]],
        "view": "timeSeries",
        "title": "sim2real behavioral widget",
        "width": width,
        "height": height,
    }

    resp = cw.get_metric_widget_image(MetricWidget=json.dumps(widget), OutputFormat="png")
    image_bytes = resp["MetricWidgetImage"]
    if hasattr(image_bytes, "read"):
        image_bytes = image_bytes.read()
    image_bytes = bytes(image_bytes)

    assert len(image_bytes) > 100, (
        f"expected a non-trivial rendered PNG payload, got {len(image_bytes)} bytes"
    )
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n", (
        f"response is not a valid PNG, header={image_bytes[:8]!r}"
    )
    chunk_type = image_bytes[12:16]
    assert chunk_type == b"IHDR", f"expected IHDR as the first PNG chunk, got {chunk_type!r}"
    ihdr_width, ihdr_height = struct.unpack(">II", image_bytes[16:24])
    assert (ihdr_width, ihdr_height) == (width, height), (
        f"rendered dimensions {(ihdr_width, ihdr_height)} do not match requested widget "
        f"size {(width, height)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
