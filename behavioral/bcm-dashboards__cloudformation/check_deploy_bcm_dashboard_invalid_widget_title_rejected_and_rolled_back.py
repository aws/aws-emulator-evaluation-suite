"""deploy-bcm-dashboard-invalid-widget-title-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-bcm-dashboard-invalid-widget-title-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["bcm-dashboards", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_VALIDATION_FAILED_ONE = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_TITLE_PATTERN = "^(?!.* {2})[a-zA-Z0-9_-][ a-zA-Z0-9_-]*[a-zA-Z0-9_-]$"


def _cost_widget(title: str) -> dict:
    return {
        "Title": title,
        "Configs": [
            {
                "QueryParameters": {
                    "CostAndUsage": {
                        "Metrics": ["UnblendedCost"],
                        "TimeRange": {
                            "StartTime": {"Type": "RELATIVE", "Value": "-P1M"},
                            "EndTime": {"Type": "RELATIVE", "Value": "-P0D"},
                        },
                        "Granularity": "MONTHLY",
                    }
                },
                "DisplayConfig": {"Table": {}},
            }
        ],
    }


def _template(name: str, title: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Dashboard": {
                "Type": "AWS::BCM::Dashboard",
                "Properties": {"Name": name, "Widgets": [_cost_widget(title)]},
            },
        },
        "Outputs": {"DashboardArn": {"Value": {"Ref": "Dashboard"}}},
    })


def _assert_cost_widget(widget: dict, title: str) -> None:
    """The widget GetDashboard returns carries every property ``_cost_widget(title)`` declared."""
    assert widget["title"] == title, f"expected widget title {title!r}, got {widget.get('title')!r}"
    assert len(widget["configs"]) == 1, f"expected one widget config, got {widget['configs']!r}"
    query = widget["configs"][0]["queryParameters"]["costAndUsage"]
    got = (query["metrics"], query["timeRange"], query["granularity"])
    want = (
        ["UnblendedCost"],
        {"startTime": {"type": "RELATIVE", "value": "-P1M"},
         "endTime": {"type": "RELATIVE", "value": "-P0D"}},
        "MONTHLY",
    )
    assert got == want, f"expected the widget's (metrics, timeRange, granularity) {want!r}, got {got!r}"
    display = widget["configs"][0]["displayConfig"]
    assert list(display) == ["table"], f"expected a table display config, got {display!r}"


def _dashboard_arns_by_name(bcm, name: str) -> list[str]:
    """Every dashboard arn ListDashboards reports under ``name``, all pages read."""
    return [d["arn"] for d in paginate(bcm, "list_dashboards", "dashboards") if d["name"] == name]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::BCM::Dashboard with a widget Title that starts with a space
    rolls back on the registry's property validation reason and creates no dashboard; a
    positive control with only that title fixed deploys and reads back through GetDashboard.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bcm-dashboard.html
    """
    bcm = ctx.client("bcm-dashboards")
    cf = ctx.client("cloudformation")

    # 1. the negative: a widget Title with a leading space violates the registry's pattern
    bad_stack = ctx.unique_name("sim2real-bcmdashneg-")
    bad_name = ctx.unique_name("sim2real-bcmdashneg-")
    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, " Leading Space"))

    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected the invalid template to roll back, stack {bad_stack!r} ended {status!r}"
    )

    reason = failed_reason(stack_events(cf, bad_id), bad_stack)
    assert reason == _VALIDATION_FAILED_ONE, (
        f"expected reason {_VALIDATION_FAILED_ONE!r}, got {reason!r}"
    )
    found = validation_rows(cf, bad_id)
    want = [(
        "Dashboard", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"Property value [ Leading Space] does not match pattern: {_TITLE_PATTERN}",
        "/Resources/Dashboard/Properties/Widgets/0/Title",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"

    never_instantiated = ("ValidationError",
                          f"Resource Dashboard does not exist for stack {bad_stack}")
    expect_error(
        lambda: cf.describe_stack_resource(StackName=bad_stack, LogicalResourceId="Dashboard"),
        *never_instantiated,
    )

    assert _dashboard_arns_by_name(bcm, bad_name) == [], (
        f"expected {bad_name!r} to never have been created in bcm-dashboards, but it is present"
    )

    delete_stack(cf, bad_id)

    # 2. the positive control: the SAME resource type, same template, only the title fixed
    good_stack = ctx.unique_name("sim2real-bcmdashpos-")
    good_name = ctx.unique_name("sim2real-bcmdashpos-")
    good_id = create_stack(ctx, cf, good_stack, _template(good_name, "Leading Space"))

    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"expected the corrected template to deploy, stack {good_stack!r} ended {status!r}"
    )
    arn = stack_outputs(cf, good_id)["DashboardArn"]

    got = bcm.get_dashboard(arn=arn)
    assert got["name"] == good_name, (
        f"expected the positive control's Name {good_name!r} to read back, got {got['name']!r}"
    )
    assert len(got["widgets"]) == 1, f"expected exactly one widget, got {got['widgets']!r}"
    _assert_cost_widget(got["widgets"][0], "Leading Space")
    listed = _dashboard_arns_by_name(bcm, good_name)
    assert listed == [arn], f"expected ListDashboards to name {good_name!r} once at the Ref, got {listed!r}"



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
