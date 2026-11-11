"""e2e-dashboard-widget-render-cleanup."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-dashboard-widget-render-cleanup"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dashboard referencing a live metric renders a real widget image, then is fully torn down."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/DashE2E-")
    metric_name = "QueueDepth"
    dashboard_name = ctx.unique_name("sim2real-behav-dash-")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 7.0, "Unit": "Count"}],
    )

    widget_properties = {
        "metrics": [[namespace, metric_name]],
        "view": "timeSeries",
        "region": ctx.region,
        "title": "sim2real-behav-widget",
        "period": 300,
        "stat": "Average",
    }
    dashboard_body = {
        "widgets": [
            {"type": "metric", "x": 0, "y": 0, "width": 6, "height": 6, "properties": widget_properties}
        ]
    }

    put_resp = cw.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(dashboard_body))
    ctx.on_cleanup(lambda: _delete_dashboard_ignore(cw, dashboard_name))
    assert put_resp["DashboardValidationMessages"] == [], (
        f"expected no validation messages for a well-formed dashboard body, "
        f"got {put_resp['DashboardValidationMessages']!r}"
    )

    got = cw.get_dashboard(DashboardName=dashboard_name)
    assert got["DashboardName"] == dashboard_name, (
        f"expected GetDashboard to echo {dashboard_name!r}, got {got['DashboardName']!r}"
    )
    parsed_body = json.loads(got["DashboardBody"])
    actual_metric = parsed_body["widgets"][0]["properties"]["metrics"][0]
    assert actual_metric == [namespace, metric_name], (
        f"expected the round-tripped widget metric to be {[namespace, metric_name]!r}, got {actual_metric!r}"
    )

    image_resp = cw.get_metric_widget_image(MetricWidget=json.dumps(widget_properties))
    image_bytes = image_resp["MetricWidgetImage"]
    if hasattr(image_bytes, "read"):
        image_bytes = image_bytes.read()
    assert len(image_bytes) > 500, "widget image unexpectedly small/empty"
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n", "widget image is not a valid PNG"

    cw.delete_dashboards(DashboardNames=[dashboard_name])
    code, message = _refusal(lambda: cw.get_dashboard(DashboardName=dashboard_name))
    assert code == "ResourceNotFound", (
        f"expected GetDashboard on a deleted dashboard to fail with ResourceNotFound, got {code!r} ({message!r})"
    )
    assert message == f"Dashboard {dashboard_name} does not exist", f"unexpected ResourceNotFound message {message!r}"


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the dashboard to be gone after delete, but the read SUCCEEDED and returned {result!r}")


def _delete_dashboard_ignore(cw, name: str) -> None:
    try:
        cw.delete_dashboards(DashboardNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
