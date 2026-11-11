"""get-metric-widget-image-invalid-request-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-widget-image-invalid-request-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage rejects a malformed `metrics` entry (a one-element array) with
    ValidationError "MetricWidget/metrics/0/0 should be object", while a well-formed widget for a
    metric with no data returns a PNG, so the rejection is about structure, not missing data."""
    cw = ctx.client("cloudwatch")
    malformed_widget = json.dumps({"metrics": [["OnlyOneElement"]], "width": 400, "height": 300})

    code, message = _err(lambda: cw.get_metric_widget_image(MetricWidget=malformed_widget))
    assert code == "ValidationError", (
        f"expected a validation-flavored rejection for a malformed MetricWidget spec, got {code}"
    )
    expected = "MetricWidget/metrics/0/0 should be object"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # A structurally well-formed widget -- even one referencing a metric with no
    # published data points -- must still succeed and return a real rendered PNG,
    # proving the rejection above is specifically about the malformed STRUCTURE,
    # not the absence of data.
    well_formed_widget = json.dumps(
        {
            "metrics": [["AWS/EC2", "CPUUtilization"]],
            "width": 400,
            "height": 300,
            "start": "-PT1H",
            "end": "PT0H",
        }
    )
    resp = cw.get_metric_widget_image(MetricWidget=well_formed_widget)
    image_bytes = bytes(resp["MetricWidgetImage"])
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n", (
        f"expected a well-formed widget request to return a real PNG, got header={image_bytes[:8]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
