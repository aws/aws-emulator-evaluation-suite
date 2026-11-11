"""cw-metric-widget-image-renders-the-published-datapoint."""
from __future__ import annotations

import json
import struct
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "cw-metric-widget-image-renders-the-published-datapoint"
GROUP = "rendering"
SERVICES = ["cloudwatch"]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """GetMetricWidgetImage output is a function of the data: new data changes the image, the same
    data re-renders byte-identically, and the requested size lands in the PNG IHDR verbatim.
    """
    cw = ctx.client("cloudwatch")
    # CloudWatch has no DeleteMetric API, so the namespace is uniquified and left behind.
    namespace = ctx.unique_name("Sim2RealDepthWidgetNs")
    metric = "RenderedSeries"
    width, height = 400, 200

    # Absolute start/end, not a relative "-PT1H": a relative window slides between the two renders
    # and would make the determinism leg untestable.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    window_end = now + timedelta(minutes=1)
    window_start = now - timedelta(minutes=20)
    widget = {
        "metrics": [[namespace, metric, {"stat": "Maximum", "period": 60}]],
        "view": "timeSeries",
        "stacked": False,
        "width": width,
        "height": height,
        "start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "region": ctx.region,
        "title": "sim2real-depth-widget",
    }
    spec = json.dumps(widget, sort_keys=True)

    def _render() -> bytes:
        return cw.get_metric_widget_image(MetricWidget=spec)["MetricWidgetImage"]

    empty_png = _render()
    assert empty_png[:8] == b"\x89PNG\r\n\x1a\n", (
        f"the widget over an empty namespace is not a PNG: first 8 bytes {empty_png[:8]!r}"
    )
    assert struct.unpack(">II", empty_png[16:24]) == (width, height), (
        f"IHDR of the empty-namespace render is "
        f"{struct.unpack('>II', empty_png[16:24])!r}, expected {(width, height)!r}"
    )

    values = [float(i) for i in range(1, 11)]
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": now - timedelta(minutes=10 - i),
                "Value": v,
                "Unit": "Count",
            }
            for i, v in enumerate(values)
        ],
    )

    def _series() -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=window_start,
            EndTime=window_end,
            Period=60,
            Statistics=["Maximum"],
        )["Datapoints"]

    datapoints = _poll_until(
        _series,
        lambda dps: len(dps) >= len(values),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"all {len(values)} published datapoints became queryable before rendering",
    )
    observed = sorted(dp["Maximum"] for dp in datapoints)
    assert observed == values, (
        f"the series the renderer will read back is {observed!r}, expected {values!r}"
    )

    full_png = _render()
    assert full_png[:8] == b"\x89PNG\r\n\x1a\n", (
        f"the widget over the populated namespace is not a PNG: {full_png[:8]!r}"
    )
    assert struct.unpack(">II", full_png[16:24]) == (width, height), (
        f"IHDR of the populated render is {struct.unpack('>II', full_png[16:24])!r}, "
        f"expected {(width, height)!r} -- the requested size must survive into the image header"
    )

    assert full_png != empty_png, (
        f"the byte-identical widget spec rendered identically ({len(full_png)} bytes) before and "
        f"after {len(values)} datapoints were published -- the renderer ignores the data, which is "
        f"exactly what a stored placeholder looks like"
    )

    # Determinism leg: a noise-emitting stub would pass the differs-from-empty leg above.
    again_png = _render()
    assert again_png == full_png, (
        f"re-rendering the same spec over the same data produced a different image "
        f"({len(full_png)} vs {len(again_png)} bytes, equal={again_png == full_png}) -- a renderer "
        f"whose output is not a function of its inputs cannot be graded, and a stub emitting noise "
        f"would pass the differs-from-empty leg above"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); raise AssertionError on exhaustion."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
