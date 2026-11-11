"""deploy-oam-sink-invalid-name-pattern-rejected-before-any-sink-is-created."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-oam-sink-invalid-name-pattern-rejected-before-any-sink-is-created"
GROUP = "deploy"
SERVICES = ["cloudformation", "oam"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_BAD_NAME = "sim2real bad name!"


def _template(name: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Sink": {"Type": "AWS::Oam::Sink", "Properties": {
                "Name": name, "Tags": {"sim2real-oam": tag_value},
            }},
        },
        "Outputs": {"SinkArn": {"Value": {"Ref": "Sink"}}},
    })


_REJECTED = [(
    "Sink", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    f"Property value [{_BAD_NAME}] does not match pattern: ^[a-zA-Z0-9_.-]+$",
    "/Resources/Sink/Properties/Name",
)]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """A CloudFormation AWS::Oam::Sink whose Name violates the registry pattern is refused by early
    validation at its exact path and no sink exists, while the same template with a valid Name
    creates one. A region holds one sink per account, so the account must start with none.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-oam-sink.html
    """
    cfn = ctx.client("cloudformation")
    oam = ctx.client("oam")
    prior = paginate(oam, "list_sinks", "Items")
    assert prior == [], f"precondition: the account already has a sink in this region: {prior!r}"

    bad_stack = ctx.unique_name("sim2real-behav-cfn-oamskbad-")
    bad_stack_id = create_stack(ctx, cfn, bad_stack, _template(_BAD_NAME, bad_stack))
    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cfn, bad_stack_id) if r[3] == "FAIL"]
    assert rows == _REJECTED, f"VALIDATION_ERROR rows {rows!r}, expected {_REJECTED!r}"
    # No sink reached OAM, read before any delete.
    assert paginate(oam, "list_sinks", "Items") == [], "a sink exists after the rejected create"

    # Positive control: the same template, Name given a valid value, creates a real sink.
    good_stack = ctx.unique_name("sim2real-behav-cfn-oamskgood-")
    good_name = ctx.unique_name("sim2real-oam-sink-")
    good_stack_id = create_stack(ctx, cfn, good_stack, _template(good_name, good_stack))
    status = wait_stack(cfn, good_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_stack_id))!r}"
    )
    ref = stack_outputs(cfn, good_stack_id)["SinkArn"]
    listed = [(s["Name"], s["Arn"]) for s in paginate(oam, "list_sinks", "Items")]
    assert listed == [(good_name, ref)], f"ListSinks {listed!r}, expected [({good_name!r}, Ref)]"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
