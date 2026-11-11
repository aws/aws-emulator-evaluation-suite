"""deploy-deadline-limit-maxcount-zero-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-deadline-limit-maxcount-zero-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "deadline"]

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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "The maxCount 0 is not -1 or an integer between 1 and 2147483647 (Service: Deadline, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)

_FARM_ARN_RE = re.compile(r"^arn:aws[a-z-]*:deadline:[a-z0-9-]+:\d+:farm/(farm-[0-9a-f]{32})$")


def _template(tag_value: str, max_count: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Farm": {"Type": "AWS::Deadline::Farm", "Properties": {
                "DisplayName": tag_value, "Tags": [{"Key": "sim2real-check", "Value": tag_value}],
            }},
            "Limit": {"Type": "AWS::Deadline::Limit", "Properties": {
                "FarmId": {"Fn::GetAtt": ["Farm", "FarmId"]},
                "DisplayName": tag_value,
                "AmountRequirementName": "amount.sim2real_slots",
                "MaxCount": max_count,
            }},
        },
        "Outputs": {
            "FarmId": {"Value": {"Fn::GetAtt": ["Farm", "FarmId"]}},
            "LimitId": {"Value": {"Fn::GetAtt": ["Limit", "LimitId"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Deadline::Limit with MaxCount 0 is rejected by Deadline's own
    validation and the stack rolls back, deleting the farm it had already created.
    """
    cfn = ctx.client("cloudformation")
    dl = ctx.client("deadline")
    tag_value = ctx.unique_name("sim2real-dllmz-")
    stack = ctx.unique_name("sim2real-dllmz-stk-")

    stack_id = create_stack(ctx, cfn, stack, _template(tag_value, 0))
    status = wait_stack(cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, stack ended in {status!r}"

    events = stack_events(cfn, stack_id)

    farm_arns = [e["PhysicalResourceId"] for e in events
                 if e["LogicalResourceId"] == "Farm" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(farm_arns) == 1, f"expected one Farm CREATE_COMPLETE event, got {len(farm_arns)}"
    match = _FARM_ARN_RE.match(farm_arns[0])
    assert match, f"Farm's PhysicalResourceId {farm_arns[0]!r} does not look like a farm ARN"
    farm_id = match.group(1)

    got_limit_reason = handler_reason(failed_reason(events, "Limit"), ctx.account)
    assert got_limit_reason == _REJECTED, (
        f"Limit CREATE_FAILED reason {got_limit_reason!r}, expected {_REJECTED!r}")

    # The rollback deleted the farm it had created, as Deadline itself reports.
    farm_gone = (
        "ResourceNotFoundException", f"Resource of type farm with id {farm_id} does not exist."
    )
    expect_error(lambda: dl.get_farm(farmId=farm_id), *farm_gone)

    # The positive control: the identical stack with a valid MaxCount deploys cleanly.
    control_tag = ctx.unique_name("sim2real-dllmz-ctrl-")
    control_stack = ctx.unique_name("sim2real-dllmz-ctrlstk-")
    control_id = create_stack(ctx, cfn, control_stack, _template(control_tag, 5))
    control_status = wait_stack(cfn, control_id)
    assert control_status == "CREATE_COMPLETE", (
        f"positive control: expected CREATE_COMPLETE, stack ended in {control_status!r}")
    control_outputs = stack_outputs(cfn, control_id)
    control_limit = dl.get_limit(
        farmId=control_outputs["FarmId"], limitId=control_outputs["LimitId"])
    got_control = (control_limit["maxCount"], control_limit["displayName"],
                   control_limit["amountRequirementName"])
    want_control = (5, control_tag, "amount.sim2real_slots")
    assert got_control == want_control, (
        f"positive control: expected (maxCount, displayName, amountRequirementName) "
        f"{want_control!r}, GetLimit reports {got_control!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
