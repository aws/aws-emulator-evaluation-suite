"""get-metric-widget-image-cross-account-metric-denied."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-widget-image-cross-account-metric-denied"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage rejects a MetricWidget payload that is not valid JSON.

    A well-formed own-account widget returns a PNG, and so does one naming an unlinked foreign
    accountId: that call is accepted, not denied.
    """
    cw = ctx.client("cloudwatch")
    malformed_widget = "{not valid json at all"

    code, message = _error_code(lambda: cw.get_metric_widget_image(MetricWidget=malformed_widget))
    assert code == "ValidationError", (
        f"expected a parameter-validation error for malformed widget JSON, got {code}"
    )
    expected = "MetricWidget property 'metricWidget' has a bad JSON content"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # positive control: a well-formed widget for the caller's own account succeeds
    own_widget = json.dumps(
        {
            "metrics": [["AWS/EC2", "CPUUtilization", {"stat": "Average"}]],
            "period": 300,
            "width": 400,
            "height": 200,
        }
    )
    resp = cw.get_metric_widget_image(MetricWidget=own_widget)
    own_image = resp["MetricWidgetImage"]
    assert len(own_image) > 0, "expected a well-formed own-account widget to return non-empty image bytes"
    assert own_image[:8] == b"\x89PNG\r\n\x1a\n", f"expected a PNG image, got signature {own_image[:8]!r}"

    # AWS accepts a widget naming an unlinked foreign accountId and renders it; it is not denied.
    sts = ctx.client("sts")
    own_account = sts.get_caller_identity()["Account"]
    foreign_account = "111111111111" if own_account != "111111111111" else "222222222222"
    cross_account_widget = json.dumps(
        {
            "metrics": [["AWS/EC2", "CPUUtilization", {"stat": "Average"}]],
            "accountId": foreign_account,
            "period": 300,
            "width": 400,
            "height": 200,
        }
    )
    cross_resp = cw.get_metric_widget_image(MetricWidget=cross_account_widget)
    cross_image = cross_resp["MetricWidgetImage"]
    assert len(cross_image) > 0, "expected a foreign-accountId widget to return non-empty image bytes, not a rejection"
    assert cross_image[:8] == b"\x89PNG\r\n\x1a\n", f"expected a PNG image, got signature {cross_image[:8]!r}"


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection for malformed MetricWidget JSON, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

