"""deploy-cloudformation-dashboard-body-matches-template."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-cloudformation-dashboard-body-matches-template"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A dashboard deployed via CFN stores exactly the widgets defined in the
    template -- GetDashboard must round-trip (preserve, byte-for-byte in
    substance) the widget layout, not a stub body."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    stack_name = ctx.unique_name("sim2real-cwdash-stack-")
    dashboard_name = ctx.unique_name("Sim2RealCwDash")

    widget = {
        "type": "text",
        "x": 0,
        "y": 0,
        "width": 6,
        "height": 3,
        "properties": {"markdown": "# sim2real behavioral fidelity check"},
    }
    body = {"widgets": [widget]}

    template = {
        "Resources": {
            "Dashboard": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {
                    "DashboardName": dashboard_name,
                    "DashboardBody": json.dumps(body),
                },
            }
        }
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    resp = cw.get_dashboard(DashboardName=dashboard_name)
    assert resp["DashboardName"] == dashboard_name, (
        f"expected DashboardName={dashboard_name!r}, got {resp['DashboardName']!r}"
    )
    actual_body = json.loads(resp["DashboardBody"])
    actual_widgets = actual_body["widgets"]
    assert len(actual_widgets) == 1, f"expected exactly 1 widget, got {len(actual_widgets)}"
    actual = actual_widgets[0]
    assert actual["type"] == "text", f"expected widget type 'text', got {actual['type']!r}"
    assert actual["x"] == 0 and actual["y"] == 0, (
        f"expected position (0, 0), got ({actual['x']}, {actual['y']})"
    )
    assert actual["width"] == 6 and actual["height"] == 3, (
        f"expected size (6, 3), got ({actual['width']}, {actual['height']})"
    )
    assert actual["properties"]["markdown"] == "# sim2real behavioral fidelity check", (
        f"expected markdown preserved verbatim, got {actual['properties']['markdown']!r}"
    )

    # A CFN-managed dashboard's teardown must actually remove the underlying
    # CloudWatch resource, not just report DELETE_COMPLETE on the stack.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})
    try:
        cw.get_dashboard(DashboardName=dashboard_name)
        gone = False
    except ClientError as exc:
        gone = exc.response.get("Error", {}).get("Code") == "ResourceNotFound"
    assert gone, "dashboard must not survive CFN stack deletion"


# ===== helpers =====

def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
