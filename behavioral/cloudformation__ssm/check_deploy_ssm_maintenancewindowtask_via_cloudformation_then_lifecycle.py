"""deploy-ssm-maintenancewindowtask-via-cloudformation-then-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssm-maintenancewindowtask-via-cloudformation-then-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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

# A one-time schedule decades away, so the window never opens while the check runs.
_SCHEDULE = "at(2099-12-31T23:59:00)"
_COMMANDS = {"commands": ["echo sim2real-mwtask"]}


def _template(window_name, tag_value, children=True):
    resources = {
        "Window": {
            "Type": "AWS::SSM::MaintenanceWindow",
            "Properties": {
                "Name": window_name, "Schedule": _SCHEDULE, "Duration": 2, "Cutoff": 1,
                "AllowUnassociatedTargets": False,
            },
        },
    }
    outputs = {"WindowId": {"Value": {"Ref": "Window"}}}
    if children:
        # A tag no managed instance carries: the target resolves to zero instances.
        resources["Target"] = {
            "Type": "AWS::SSM::MaintenanceWindowTarget",
            "Properties": {
                "WindowId": {"Ref": "Window"}, "ResourceType": "INSTANCE",
                "Targets": [{"Key": "tag:sim2real-mwtask-target", "Values": [tag_value]}],
            },
        }
        resources["Task"] = {
            "Type": "AWS::SSM::MaintenanceWindowTask",
            "Properties": {
                "WindowId": {"Ref": "Window"}, "Priority": 1, "TaskType": "RUN_COMMAND",
                "TaskArn": "AWS-RunShellScript", "MaxConcurrency": "1", "MaxErrors": "1",
                "Targets": [{"Key": "WindowTargetIds", "Values": [{"Ref": "Target"}]}],
                "TaskInvocationParameters": {
                    "MaintenanceWindowRunCommandParameters": {"Parameters": _COMMANDS}
                },
            },
        }
        outputs["TargetId"] = {"Value": {"Ref": "Target"}}
        outputs["TaskId"] = {"Value": {"Ref": "Task"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(ssm, resource_type, resource_id):
    rows = ssm.list_tags_for_resource(ResourceType=resource_type, ResourceId=resource_id)
    return {t["Key"]: t["Value"] for t in rows["TagList"] if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation SSM maintenance window, target and task read back through SSM.

    Ref and every templated property match; an update dropping target and task empties the
    window's listings while it answers, and the stack delete removes the window.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-ssmmwtask-stack-")
    window_name = ctx.unique_name("sim2real-ssmmwtask-")
    tag_value = ctx.unique_name("sim2real-mwtask-notarget-")

    stack_id = create_stack(ctx, cfn, stack, _template(window_name, tag_value))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    window_id, target_id, task_id = out["WindowId"], out["TargetId"], out["TaskId"]

    # Window: Ref == the id an independent name-filtered listing reports; properties and tags.
    windows = paginate(ssm, "describe_maintenance_windows", "WindowIdentities",
                       Filters=[{"Key": "Name", "Values": [window_name]}])
    assert [w["WindowId"] for w in windows] == [window_id], f"windows {windows!r}"
    window = ssm.get_maintenance_window(WindowId=window_id)
    got = {k: window[k] for k in ("Name", "Schedule", "Duration", "Cutoff",
                                  "AllowUnassociatedTargets")}
    want = {"Name": window_name, "Schedule": _SCHEDULE, "Duration": 2, "Cutoff": 1,
            "AllowUnassociatedTargets": False}
    assert got == want, f"maintenance window reads {got!r}, expected {want!r}"
    window_tags = _own_tags(ssm, "MaintenanceWindow", window_id)
    assert window_tags == {"sim2real": stack}, f"window tags {window_tags!r}"

    # Target and task: Ref == the one entry each window listing reports; properties match.
    targets = paginate(ssm, "describe_maintenance_window_targets", "Targets", WindowId=window_id)
    got = [(t["WindowTargetId"], t["ResourceType"], t["Targets"]) for t in targets]
    want = [(target_id, "INSTANCE",
             [{"Key": "tag:sim2real-mwtask-target", "Values": [tag_value]}])]
    assert got == want, f"window targets {got!r}, expected {want!r}"
    tasks = paginate(ssm, "describe_maintenance_window_tasks", "Tasks", WindowId=window_id)
    assert [t["WindowTaskId"] for t in tasks] == [task_id], f"window tasks {tasks!r}"
    task = ssm.get_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id)
    got = {k: task[k] for k in ("TaskType", "TaskArn", "Priority", "MaxConcurrency", "MaxErrors",
                                "Targets")}
    got["Parameters"] = task["TaskInvocationParameters"]["RunCommand"]["Parameters"]
    want = {"TaskType": "RUN_COMMAND", "TaskArn": "AWS-RunShellScript", "Priority": 1,
            "MaxConcurrency": "1", "MaxErrors": "1",
            "Targets": [{"Key": "WindowTargetIds", "Values": [target_id]}],
            "Parameters": _COMMANDS}
    assert got == want, f"maintenance window task reads {got!r}, expected {want!r}"

    # Children first: dropping target and task empties both listings while the window answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(window_name, tag_value, children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    left = paginate(ssm, "describe_maintenance_window_tasks", "Tasks", WindowId=window_id)
    assert left == [], f"window tasks after the update: {left!r}"
    left = paginate(ssm, "describe_maintenance_window_targets", "Targets", WindowId=window_id)
    assert left == [], f"window targets after the update: {left!r}"
    created = ssm.get_maintenance_window(WindowId=window_id)["CreatedDate"]
    assert created == window["CreatedDate"], (
        f"window after the update reads CreatedDate {created!r}, before {window['CreatedDate']!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("DoesNotExistException", f"Maintenance window {window_id} does not exist")
    expect_error(lambda: ssm.get_maintenance_window(WindowId=window_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
