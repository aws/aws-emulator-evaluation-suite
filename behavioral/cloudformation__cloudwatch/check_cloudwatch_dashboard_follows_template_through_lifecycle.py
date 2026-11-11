"""cloudwatch-dashboard-follows-template-through-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudwatch-dashboard-follows-template-through-lifecycle"
GROUP = "deploy_functional"
SERVICES = ["cloudformation", "cloudwatch"]


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _template(widget_text: str) -> str:
    body = json.dumps({
        "widgets": [{"type": "text", "properties": {"markdown": widget_text}}],
    })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "DashboardName": {"Type": "String"},
            "Team": {"Type": "String"},
        },
        "Resources": {
            "Dashboard": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {
                    "DashboardName": {"Ref": "DashboardName"},
                    "DashboardBody": body,
                    "Tags": [{"Key": "team", "Value": {"Ref": "Team"}}],
                },
            },
        },
        "Outputs": {"DashboardRef": {"Value": {"Ref": "Dashboard"}}},
    })


def _wait_terminal(cf, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(3)
    raise AssertionError(f"stack {name} terminal not reached within {timeout_s}s (last={last!r})")


def _outputs(cf, name) -> dict:
    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _dashboard_missing(cw, name) -> bool:
    try:
        cw.get_dashboard(DashboardName=name)
        return False
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFound":
            return True
        raise


def _poll_until(fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return True
        time.sleep(interval_s)
    return False


def _poll_error(fn, *, timeout_s: float, interval_s: float = 3.0) -> tuple[str, str]:
    """Call fn() until it raises a ClientError and return (code, message); success past the
    deadline fails."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code", "<no code>"), err.get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"still succeeding after {timeout_s}s")
        time.sleep(interval_s)


def _delete_stack_if_present(cf, stack_name: str) -> None:
    try:
        cf.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return
        raise
    cf.delete_stack(StackName=stack_name)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A stack-managed dashboard is created, updated in place on a body/tag change, replaced (old
    one deleted) on a name change, and removed on stack delete; Ref resolves to the name.
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-xsvc-cwdash-")
    dash_v1 = ctx.unique_name("sim2real-xsvc-cwdash-v1-")
    dash_v2 = ctx.unique_name("sim2real-xsvc-cwdash-v2-")

    ctx.on_cleanup(lambda: _delete_stack_if_present(cf, stack_name))
    # Safety net: a stack delete that fails to clean up the dashboard still leaves these gone.
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dash_v1]) if not _dashboard_missing(cw, dash_v1) else None)
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dash_v2]) if not _dashboard_missing(cw, dash_v2) else None)

    def _create_params(name, team):
        return [
            {"ParameterKey": "DashboardName", "ParameterValue": name},
            {"ParameterKey": "Team", "ParameterValue": team},
        ]

    # ---- 1. create ----
    cf.create_stack(
        StackName=stack_name, TemplateBody=_template("Requests"),
        Parameters=_create_params(dash_v1, "platform"),
    )
    status = _wait_terminal(cf, stack_name)
    assert status == "CREATE_COMPLETE", f"stack status after create is {status!r}"

    outputs = _outputs(cf, stack_name)
    assert outputs["DashboardRef"] == dash_v1, (
        f"Ref is {outputs['DashboardRef']!r}, expected the dashboard name {dash_v1!r}"
    )
    created = cw.get_dashboard(DashboardName=dash_v1)
    body = json.loads(created["DashboardBody"])
    assert body["widgets"][0]["properties"]["markdown"] == "Requests", (
        f"created dashboard body is {created['DashboardBody']!r}"
    )
    dash_arn = created["DashboardArn"]
    created_tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(
        ResourceARN=dash_arn
    )["Tags"]}
    assert created_tags.get("team") == "platform", f"created dashboard tags are {created_tags!r}"

    # ---- 2. in-place update: body and tag change, same physical dashboard ----
    cf.update_stack(
        StackName=stack_name, TemplateBody=_template("Errors"),
        Parameters=_create_params(dash_v1, "data"),
    )
    status = _wait_terminal(cf, stack_name)
    assert status == "UPDATE_COMPLETE", f"stack status after the body/tag update is {status!r}"
    outputs = _outputs(cf, stack_name)
    assert outputs["DashboardRef"] == dash_v1, (
        f"a body/tag update changed Ref to {outputs['DashboardRef']!r}, expected {dash_v1!r} "
        "unchanged"
    )
    updated = cw.get_dashboard(DashboardName=dash_v1)
    assert json.loads(updated["DashboardBody"])["widgets"][0]["properties"]["markdown"] == (
        "Errors"
    ), f"updated dashboard body is {updated['DashboardBody']!r}, expected the 'Errors' widget"
    updated_tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(
        ResourceARN=dash_arn
    )["Tags"]}
    assert updated_tags.get("team") == "data", f"updated dashboard tags are {updated_tags!r}"

    # ---- 3. a name change replaces the dashboard ----
    cf.update_stack(
        StackName=stack_name, TemplateBody=_template("Errors"),
        Parameters=_create_params(dash_v2, "data"),
    )
    status = _wait_terminal(cf, stack_name)
    assert status == "UPDATE_COMPLETE", f"stack status after the rename is {status!r}"
    outputs = _outputs(cf, stack_name)
    assert outputs["DashboardRef"] == dash_v2, (
        f"a name change left Ref at {outputs['DashboardRef']!r}, expected the new name "
        f"{dash_v2!r}"
    )
    renamed = cw.get_dashboard(DashboardName=dash_v2)
    assert json.loads(renamed["DashboardBody"])["widgets"][0]["properties"]["markdown"] == (
        "Errors"
    ), f"renamed dashboard body is {renamed['DashboardBody']!r}"
    gone = _poll_until(lambda: _dashboard_missing(cw, dash_v1))
    assert gone, f"the displaced dashboard {dash_v1!r} was not deleted once the rename committed"

    # ---- 4. stack delete removes the surviving dashboard ----
    cf.delete_stack(StackName=stack_name)
    code, message = _poll_error(lambda: cf.describe_stacks(StackName=stack_name), timeout_s=180.0)
    assert code == "ValidationError", (
        f"describe_stacks on the deleted stack raised {code!r}, expected ValidationError"
    )
    want = f"Stack with id {stack_name} does not exist"
    assert message == want, f"describe_stacks on the deleted stack said {message!r}, expected {want!r}"
    gone = _poll_until(lambda: _dashboard_missing(cw, dash_v2))
    assert gone, f"the stack delete did not remove the dashboard {dash_v2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
