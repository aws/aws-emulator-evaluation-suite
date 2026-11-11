"""deploy-ec2-instance-event-window-time-range-too-short-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-event-window-time-range-too-short-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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


_REJECTED = (
    "Time Ranges should have at-least 4 hours difference. (Service: EC2; "
    "Operation: CreateInstanceEventWindow; Status Code: 400; "
    "Error Code: InvalidInstanceEventWindowTimeRange; Request ID: <id>)",
    "InvalidRequest",
)
_TIME_RANGE_OK = {"StartWeekDay": "monday", "StartHour": 0, "EndWeekDay": "monday", "EndHour": 4}

def _template(name: str, *, start_hour: int, end_hour: int) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Iew": {"Type": "AWS::EC2::InstanceEventWindow", "Properties": {
                "Name": name,
                "TimeRanges": [{
                    "StartWeekDay": "monday", "StartHour": start_hour,
                    "EndWeekDay": "monday", "EndHour": end_hour,
                }],
                "Tags": [{"Key": "sim2real-res", "Value": name}],
            }},
        },
        "Outputs": {
            "Arn": {"Value": {"Ref": "Iew"}},
            "Id": {"Value": {"Fn::GetAtt": ["Iew", "InstanceEventWindowId"]}},
        },
    }


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN instance event window naming a sub-4-hour time range is rejected by EC2 and the
    stack creates no window of its own; the identical shape with a 4-hour range succeeds.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    broken_name = ctx.unique_name("sim2real-xsvc-iewshort-")
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-iewshortstack-"),
                            json.dumps(_template(broken_name, start_hour=2, end_hour=4)))
    status = wait_stack(cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"a 2-hour time range ended {status!r}"
    events = stack_events(cfn, stack_id)
    failed = decisive_rows(events)
    assert [r for r in failed if r[1] == "CREATE_FAILED"] == [("Iew", "CREATE_FAILED")], (
        f"expected exactly the event window to fail creation: {failed!r}"
    )
    got = handler_reason(failed_reason(events, "Iew"), ctx.account, broken_name)
    assert got == _REJECTED, f"CREATE_FAILED reason {got!r}, expected {_REJECTED!r}"

    # Effect-absent before this check's delete: no window carries the rejected template's tag.
    tagged = paginate(ec2, "describe_instance_event_windows", "InstanceEventWindows",
                      Filters=[{"Name": "tag:sim2real-res", "Values": [broken_name]}])
    assert tagged == [], f"a window tagged with the rejected template's tag exists: {tagged!r}"
    delete_stack(cfn, stack_id)

    # Positive control: the same template with a 4-hour range deploys and reads back.
    control_name = ctx.unique_name("sim2real-xsvc-ieok-")
    control_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-ieokstack-"),
                              json.dumps(_template(control_name, start_hour=0, end_hour=4)))
    status = wait_stack(cfn, control_id)
    assert status == "CREATE_COMPLETE", f"the same shape with a 4-hour range ended {status!r}"
    outputs = stack_outputs(cfn, control_id)
    partition = control_id.split(":")[1]
    found = paginate(ec2, "describe_instance_event_windows", "InstanceEventWindows",
                     Filters=[{"Name": "tag:sim2real-res", "Values": [control_name]}])
    assert [w["InstanceEventWindowId"] for w in found] == [outputs["Id"]], (
        f"windows tagged {control_name!r}: {found!r}, GetAtt Id {outputs['Id']!r}"
    )
    want_arn = (f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:"
                f"instance-event-window/{outputs['Id']}")
    assert outputs["Arn"] == want_arn, f"Ref {outputs['Arn']!r}, expected {want_arn!r}"
    window = found[0]
    got = (window["Name"], window["TimeRanges"],
           {"Key": "sim2real-res", "Value": control_name} in window.get("Tags", []))
    assert got == (control_name, [_TIME_RANGE_OK], True), f"EC2 reports window {got!r}"

    delete_stack(cfn, control_id)
    instance_event_windows_gone = (
        "InvalidInstanceEventWindowIDNotFound",
        f"Invalid Instance Event Window IDs [{outputs['Id']}].",
    )
    expect_error(
        lambda: ec2.describe_instance_event_windows(InstanceEventWindowIds=[outputs["Id"]]),
        *instance_event_windows_gone,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
