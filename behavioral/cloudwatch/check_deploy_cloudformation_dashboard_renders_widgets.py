"""deploy-cloudformation-dashboard-renders-widgets."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-dashboard-renders-widgets"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed dashboard returns its exact widget JSON from GetDashboard, its
    metric widget renders to a PNG via GetMetricWidgetImage, and stack deletion removes it."""
    dashboard_name = ctx.unique_name("Sim2RealBehavDash")
    marker = ctx.unique_name("sim2real-behav-marker-")
    namespace = ctx.unique_name("Sim2RealBehavDashNS")
    metric_name = ctx.unique_name("sim2real-behav-dash-metric-")

    metric_widget_properties = {
        "metrics": [[namespace, metric_name]],
        "period": 300,
        "stat": "Average",
        "view": "timeSeries",
        "title": marker,
        "region": ctx.region,
    }
    dashboard_body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": f"# {marker}"},
            },
            {
                "type": "metric",
                "x": 6,
                "y": 0,
                "width": 6,
                "height": 6,
                "properties": metric_widget_properties,
            },
        ]
    }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TestDashboard": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {
                    "DashboardName": dashboard_name,
                    "DashboardBody": json.dumps(dashboard_body),
                },
            }
        },
    }
    stack_name = _deploy_cfn(ctx, template)

    cw = ctx.client("cloudwatch")
    resp = cw.get_dashboard(DashboardName=dashboard_name)
    assert resp["DashboardName"] == dashboard_name, (
        f"expected GetDashboard to name {dashboard_name!r}, got {resp['DashboardName']!r}"
    )
    body = json.loads(resp["DashboardBody"])
    assert body == dashboard_body, f"widget JSON round-trip mismatch: {body!r}"

    # The metric widget CFN wrote into the dashboard must actually RENDER to a real
    # image -- proving the managed resource is live, not just a stored JSON blob.
    stored_properties = body["widgets"][1]["properties"]

    def _render(properties: dict[str, Any]) -> bytes:
        image_bytes = cw.get_metric_widget_image(MetricWidget=json.dumps(properties))[
            "MetricWidgetImage"
        ]
        if hasattr(image_bytes, "read"):
            image_bytes = image_bytes.read()
        return image_bytes

    # A relative window draws a time axis that moves between renders, so every render uses
    # the same absolute, already-elapsed window and two renders differ only by the widget.
    window_end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    window = {
        "start": (window_end - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    image_bytes = _render({**stored_properties, **window})
    assert len(image_bytes) > 100, f"widget image implausibly small/empty: {len(image_bytes)} bytes"
    assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n", (
        f"widget did not render a valid PNG, got {image_bytes[:8]!r}"
    )
    # The image is a function of the widget: the same widget renders the same bytes, and the
    # same widget under a different title renders different bytes, which a fixed placeholder
    # PNG does not.
    again_bytes = _render({**stored_properties, **window})
    assert again_bytes == image_bytes, (
        f"the same widget over the same window rendered {len(again_bytes)} bytes, then "
        f"{len(image_bytes)} different bytes, so the retitled comparison below would grade nothing"
    )
    retitled_bytes = _render({**stored_properties, **window, "title": f"{marker}-retitled"})
    assert retitled_bytes != image_bytes, (
        f"the stored widget and the same widget retitled rendered byte-identical images "
        f"({len(image_bytes)} bytes, first 8 {image_bytes[:8]!r}): the render ignores the widget"
    )

    # Deleting the stack must remove the live resource, not just the CFN record.
    _delete_stack_and_wait(ctx, stack_name)
    not_found_code, not_found_message = _client_error(
        lambda: cw.get_dashboard(DashboardName=dashboard_name)
    )
    assert not_found_code == "ResourceNotFound", (
        f"expected the dashboard to be gone after stack delete, got {not_found_code}"
    )
    expected_message = f"Dashboard {dashboard_name} does not exist"
    assert not_found_message == expected_message, (
        f"expected message {expected_message!r}, got {not_found_message!r}"
    )


def _deploy_cfn(ctx: Any, template: dict[str, Any]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    except Exception as exc:  # surface the real CFN failure reason
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e.get('LogicalResourceId')}: {e.get('ResourceStatus')} - {e.get('ResourceStatusReason')}"
            for e in events
            if e.get("ResourceStatusReason")
        ]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc
    return stack_name


def _delete_stack_and_wait(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
