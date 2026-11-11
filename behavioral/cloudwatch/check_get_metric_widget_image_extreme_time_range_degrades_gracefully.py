"""get-metric-widget-image-extreme-time-range-degrades-gracefully."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-metric-widget-image-extreme-time-range-degrades-gracefully"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage accepts a widget whose time range (900 days) spans past CloudWatch's 15-month
    retention and returns a well-formed PNG: the API reference signals data that cannot load with an
    in-image warning, not an API error."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavWidget-")
    widget = {
        "metrics": [[namespace, "NoSuchMetric"]],
        "period": 60,
        "start": "-P900D",  # ~2.5 years: beyond the documented 15-month retention
        "end": "PT0H",
        "width": 400,
        "height": 300,
    }
    resp = cw.get_metric_widget_image(
        MetricWidget=_json_dumps(widget), OutputFormat="png"
    )
    image_bytes = resp["MetricWidgetImage"]
    # boto3 auto-decodes the Base64-encoded blob response field to raw bytes.
    assert isinstance(image_bytes, (bytes, bytearray)) and len(image_bytes) > 0, (
        f"expected a non-empty rendered image for an extreme (~2.5yr) time range, "
        f"got type={type(image_bytes).__name__} len={len(image_bytes) if image_bytes else 0}"
    )
    assert bytes(image_bytes[:8]) == b"\x89PNG\r\n\x1a\n", "response is not a valid PNG image"


def _json_dumps(obj) -> str:
    import json

    return json.dumps(obj)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
