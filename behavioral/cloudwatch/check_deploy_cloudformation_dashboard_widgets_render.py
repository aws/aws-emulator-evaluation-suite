"""deploy-cloudformation-dashboard-widgets-render."""
from __future__ import annotations

import json
import struct
import time

from behavioral_harness import tags


CHECK = "deploy-cloudformation-dashboard-widgets-render"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


def _widget_properties(region: str) -> dict:
    return {
        "metrics": [["AWS/EC2", "CPUUtilization"]],
        "period": 300,
        "stat": "Average",
        "region": region,
        "title": "Sim2Real Test Widget",
        "view": "timeSeries",
        "width": 6,
        "height": 6,
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed dashboard keeps its widget properties unchanged, the stored widget
    renders to a PNG that tracks the requested size, and stack deletion removes the dashboard."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    dashboard_name = ctx.unique_name("sim2real-cfn-dash-")
    stack_name = ctx.unique_name("sim2real-cfn-dashstack-")

    widget_props = _widget_properties(ctx.region)
    dashboard_body = {"widgets": [{"type": "metric", "x": 0, "y": 0, "width": 6, "height": 6, "properties": widget_props}]}

    template = json.dumps(
        {
            "Parameters": {
                "DashboardName": {"Type": "String"},
                "DashboardBody": {"Type": "String"},
            },
            "Resources": {
                "TestDashboard": {
                    "Type": "AWS::CloudWatch::Dashboard",
                    "Properties": {
                        "DashboardName": {"Ref": "DashboardName"},
                        "DashboardBody": {"Ref": "DashboardBody"},
                    },
                }
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "DashboardName", "ParameterValue": dashboard_name},
            {"ParameterKey": "DashboardBody", "ParameterValue": json.dumps(dashboard_body)},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    # Compare the whole properties dict so dropped or mangled widget keys are caught.
    got = cw.get_dashboard(DashboardName=dashboard_name)
    assert got["DashboardName"] == dashboard_name, (
        f"expected dashboard name {dashboard_name!r}, got {got['DashboardName']!r}"
    )
    got_body = json.loads(got["DashboardBody"])
    assert len(got_body["widgets"]) == 1, f"expected exactly 1 widget, got {len(got_body['widgets'])}"
    got_properties = got_body["widgets"][0]["properties"]
    assert got_properties == widget_props, (
        f"widget properties round-trip mismatch: {got_properties!r} != {widget_props!r}"
    )

    # Render the persisted properties, not the local copy, so a corrupted stored body is caught.
    image_resp = cw.get_metric_widget_image(MetricWidget=json.dumps(got_properties))
    image_bytes = image_resp["MetricWidgetImage"].read() if hasattr(image_resp["MetricWidgetImage"], "read") else image_resp["MetricWidgetImage"]
    assert len(image_bytes) > 100, f"widget image is implausibly small/empty: {len(image_bytes)} bytes"
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n", f"widget did not render a valid PNG, header was {image_bytes[:8]!r}"
    # The image is a function of the widget: the same widget at 400x200 renders a PNG whose IHDR
    # carries that size and whose bytes differ from the stored widget's render, which a fixed
    # placeholder PNG does not.
    resized = cw.get_metric_widget_image(MetricWidget=json.dumps({**got_properties, "width": 400, "height": 200}))["MetricWidgetImage"]
    resized = resized.read() if hasattr(resized, "read") else resized
    assert resized[:8] == b"\x89PNG\r\n\x1a\n", f"resized widget did not render a valid PNG, header was {resized[:8]!r}"
    resized_size = struct.unpack(">II", resized[16:24])
    assert resized_size == (400, 200), f"IHDR of the 400x200 render is {resized_size!r}"
    assert resized != image_bytes, (
        f"the stored widget and the same widget at 400x200 rendered byte-identical images ({len(image_bytes)} bytes)"
    )

    # Stack deletion must remove the dashboard itself.
    _delete_stack(ctx, stack_name)
    code, message = _client_error(lambda: cw.get_dashboard(DashboardName=dashboard_name))
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound after stack deletion, got {code!r}"
    )
    expected_message = f"Dashboard {dashboard_name} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _wait_for_stack_status(ctx, stack_name: str, ok_statuses: set[str], timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        assert stacks, f"stack {stack_name} disappeared"
        last_status = stacks[0]["StackStatus"]
        if last_status in ok_statuses:
            return
        if last_status.endswith("FAILED") or last_status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} reached {last_status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last was {last_status}")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 180.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        status = stacks[0]["StackStatus"] if stacks else "DELETE_COMPLETE"
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    over-permissive target cannot pass as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
