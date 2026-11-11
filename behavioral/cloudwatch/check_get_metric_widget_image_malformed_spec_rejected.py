"""get-metric-widget-image-malformed-spec-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-metric-widget-image-malformed-spec-rejected"
GROUP = "server-side"
SERVICES = ["cloudwatch"]

_MALFORMED_MESSAGE = "MetricWidget property 'metricWidget' has a bad JSON content"
_EMPTY_MESSAGE = "Should have required property 'metrics'"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """GetMetricWidgetImage with syntactically invalid widget JSON is rejected, not rendered blank."""
    cw = ctx.client("cloudwatch")

    # Positive control first: a well-formed widget must still render, so the rejections below
    # are proven to be about the malformed spec, not a target that refuses every call.
    well_formed = json.dumps(
        {"metrics": [["AWS/EC2", "CPUUtilization"]], "width": 400, "height": 300}
    )
    resp = cw.get_metric_widget_image(MetricWidget=well_formed)
    image_bytes = resp["MetricWidgetImage"]
    assert len(image_bytes) > 0, "expected a well-formed widget to render non-empty image bytes"

    code, message = _error(lambda: cw.get_metric_widget_image(MetricWidget="{this is not valid json"))
    assert code == "ValidationError", (
        f"expected a parameter-validation error for malformed widget JSON, got {code}"
    )
    assert message == _MALFORMED_MESSAGE, f"unexpected message for malformed widget JSON: {message!r}"

    # A structurally valid JSON object that is nonetheless a nonsensical widget (missing the
    # required "metrics" field) should also be rejected rather than silently producing a blank
    # or garbled image.
    code_empty, message_empty = _error(lambda: cw.get_metric_widget_image(MetricWidget="{}"))
    assert code_empty == "ValidationError", (
        f"expected a parameter-validation error for a widget spec with no metrics, got {code_empty}"
    )
    assert message_empty == _EMPTY_MESSAGE, (
        f"unexpected message for a widget spec with no metrics: {message_empty!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
