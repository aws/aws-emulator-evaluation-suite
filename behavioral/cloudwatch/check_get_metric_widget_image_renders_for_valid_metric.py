"""get-metric-widget-image-renders-for-valid-metric."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-metric-widget-image-renders-for-valid-metric"
GROUP = "server-side"
SERVICES = ["cloudwatch"]

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MALFORMED_MESSAGE = "MetricWidget property 'metricWidget' has a bad JSON content"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage returns a PNG that grows by more than 200 bytes once the queried metric has
    a datapoint, and rejects a widget that is not valid JSON with ValidationError "MetricWidget
    property 'metricWidget' has a bad JSON content" instead of rendering a blank chart."""
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealBehavWidget")
    metric_name = "WidgetMetric"

    def widget_json() -> str:
        return json.dumps({
            "metrics": [[namespace, metric_name]],
            "title": "sim2real-widget-check",
            "view": "timeSeries",
            "width": 400,
            "height": 200,
        })

    baseline = bytes(cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"])
    assert baseline[:8] == _PNG_SIGNATURE, (
        f"baseline (no published datapoint) render is not a valid PNG, header={baseline[:8]!r}"
    )

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 42.0, "Unit": "Count"}],
    )

    after = _poll_until(
        lambda: bytes(cw.get_metric_widget_image(MetricWidget=widget_json())["MetricWidgetImage"]),
        lambda image: len(image) > len(baseline) + 200,
        timeout_s=120,
        interval_s=5,
        description="rendered widget growing once WidgetMetric has a published datapoint",
    )
    assert after[:8] == _PNG_SIGNATURE, f"rendered image is not a valid PNG, header={after[:8]!r}"
    assert after != baseline, "widget image bytes did not change after publishing a datapoint"

    # A structurally invalid widget document must be rejected outright, not rendered as a blank
    # or garbled image.
    error = _client_error(lambda: cw.get_metric_widget_image(MetricWidget="{not valid json"))
    code = error.get("Code")
    assert code == "ValidationError", (
        f"expected ValidationError for malformed widget JSON, got {code!r}"
    )
    assert error.get("Message") == _MALFORMED_MESSAGE, (
        f"unexpected message for malformed widget JSON: {error.get('Message')!r}"
    )


from botocore.exceptions import ClientError  # noqa: E402


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {len(last) if last else 0} bytes")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"expected malformed MetricWidget JSON to be rejected, but the call succeeded and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
