"""cfn-changeset-resource-type-provisions-real-change-set."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-changeset-resource-type-provisions-real-change-set"
GROUP = "cloudformation"
SERVICES = ["cloudformation"]

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

_TARGET_V1 = {"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}
_TARGET_V2 = {"Resources": {
    "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
    "Handle2": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
}}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A declared AWS::CloudFormation::ChangeSet resource creates a real, un-executed change set.

    Ref is the ListChangeSets entry's id, the change set holds the declared template and proposes
    exactly its new resource; deleting the holder removes it and leaves the target untouched.
    """
    cfn = ctx.client("cloudformation")
    target_name = ctx.unique_name("sim2real-behav-cfncs-target-")
    cs_name = ctx.unique_name("sim2real-behav-cfncs-cs-")

    target_id = create_stack(ctx, cfn, target_name, json.dumps(_TARGET_V1))
    status = wait_stack(cfn, target_id)
    assert status == "CREATE_COMPLETE", f"target stack ended {status!r}"
    holder_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfncs-holder-"), json.dumps({
        "Resources": {"CS": {"Type": "AWS::CloudFormation::ChangeSet", "Properties": {
            "StackName": target_name, "ChangeSetName": cs_name,
            "TemplateBody": json.dumps(_TARGET_V2),
        }}},
        "Outputs": {"CSId": {"Value": {"Ref": "CS"}}},
    }))
    status = wait_stack(cfn, holder_id)
    assert status == "CREATE_COMPLETE", f"holder stack ended {status!r}"
    cs_id = stack_outputs(cfn, holder_id)["CSId"]

    # Ref against an independent read: the target stack's change set list, found by name.
    listed = [c for c in paginate(cfn, "list_change_sets", "Summaries", StackName=target_id)
              if c["ChangeSetName"] == cs_name]
    assert [c["ChangeSetId"] for c in listed] == [cs_id], (
        f"ListChangeSets named {cs_name!r}: {listed!r}; Ref {cs_id!r}"
    )
    detail = cfn.describe_change_set(ChangeSetName=cs_name, StackName=target_id)
    got = (detail["ChangeSetId"], detail["ChangeSetName"], detail["StackId"], detail["Status"],
           detail["ExecutionStatus"])
    assert got == (cs_id, cs_name, target_id, "CREATE_COMPLETE", "AVAILABLE"), f"change set {got!r}"
    changes = [(c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"],
                c["ResourceChange"]["ResourceType"]) for c in detail["Changes"]]
    assert changes == [("Add", "Handle2", "AWS::CloudFormation::WaitConditionHandle")], (
        f"proposed changes {changes!r}"
    )
    body = cfn.get_template(StackName=target_id, ChangeSetName=cs_id,
                            TemplateStage="Original")["TemplateBody"]
    body = json.loads(body) if isinstance(body, str) else body
    assert body == _TARGET_V2, f"the change set's template {body!r} != the declared {_TARGET_V2!r}"

    # Deleting the holder removes the un-executed change set; the target keeps only Handle.
    delete_stack(cfn, holder_id)
    change_set_gone = ("ChangeSetNotFound", f"ChangeSet [{cs_id}] does not exist")
    expect_error(lambda: cfn.describe_change_set(ChangeSetName=cs_id), *change_set_gone)
    target_resources = sorted(r["LogicalResourceId"] for r in paginate(
        cfn, "list_stack_resources", "StackResourceSummaries", StackName=target_id))
    target_status = cfn.describe_stacks(StackName=target_id)["Stacks"][0]["StackStatus"]
    assert (target_resources, target_status) == (["Handle"], "CREATE_COMPLETE"), (
        f"target stack after the holder delete: {target_resources!r}, {target_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
