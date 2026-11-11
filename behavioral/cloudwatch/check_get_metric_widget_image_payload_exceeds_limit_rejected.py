"""get-metric-widget-image-payload-exceeds-limit-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-widget-image-payload-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

_LIMIT_BYTES = 102400


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricWidgetImage rejects a MetricWidget over the documented 100 KB uncompressed payload
    limit with RequestEntityTooLarge; a small widget succeeds and returns non-empty image bytes.
    """
    cw = ctx.client("cloudwatch")

    def _widget(title_len: int) -> str:
        return json.dumps(
            {
                "metrics": [["AWS/EC2", "CPUUtilization", "InstanceId", "i-sim2real00000000001"]],
                "width": 400,
                "height": 300,
                "period": 300,
                "title": "T" * title_len,
            }
        )

    # AWS refuses this at the transport layer (RequestEntityTooLarge, not ValidationError), and
    # the message names the request body size the client sent, so capture it.
    sent_sizes: list[int] = []

    def _record_body_size(request, **_kwargs):
        body = request.body
        sent_sizes.append(len(body) if body is not None else 0)

    cw.meta.events.register("before-send.cloudwatch.GetMetricWidgetImage", _record_body_size)
    try:
        code, message = _error(lambda: cw.get_metric_widget_image(MetricWidget=_widget(150_000)))
    finally:
        cw.meta.events.unregister("before-send.cloudwatch.GetMetricWidgetImage", _record_body_size)
    assert code == "RequestEntityTooLarge", f"expected RequestEntityTooLarge, got {code}"
    assert sent_sizes, "expected the oversized GetMetricWidgetImage request to be sent"
    expected = f"Request size {sent_sizes[-1]} exceeded {_LIMIT_BYTES} bytes"
    assert message == expected, f"unexpected RequestEntityTooLarge message: {message!r}, expected {expected!r}"

    resp = cw.get_metric_widget_image(MetricWidget=_widget(10))
    image_bytes = resp["MetricWidgetImage"]
    assert len(image_bytes) > 0, f"expected non-empty image bytes for an in-limit widget, got {len(image_bytes)}"


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
