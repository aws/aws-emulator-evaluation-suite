"""deploy-iot-command-round-trip-then-pending-deletion."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "deploy-iot-command-round-trip-then-pending-deletion"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

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


# ---- Check-specific: the template, then run(). ----

def _template(command_id, display_name, content):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Command": {
                "Type": "AWS::IoT::Command",
                "Properties": {
                    "CommandId": command_id,
                    "Namespace": "AWS-IoT",
                    "DisplayName": display_name,
                    "Payload": {"Content": content, "ContentType": "application/json"},
                },
            },
        },
        "Outputs": {
            "CommandRef": {"Value": {"Ref": "Command"}},
            "CommandArn": {"Value": {"Fn::GetAtt": ["Command", "CommandArn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation IoT command reads back through IoT, then the stack delete tombstones it.

    Ref, GetAtt and every templated property match IoT; the deleted command stays readable as
    the documented deprecated-and-pending-deletion tombstone rather than disappearing outright.
    """
    cf = ctx.client("cloudformation")
    iot = ctx.client("iot")
    stack = ctx.unique_name("sim2real-cfniotcmd-")
    command_id = ctx.unique_name("sim2realcfniotcmd")
    display_name = "sim2real command round trip"
    content = json.dumps({"action": "sim2real-noop"})
    content_b64 = base64.b64encode(content.encode()).decode()

    stack_id = create_stack(ctx, cf, stack, _template(command_id, display_name, content_b64))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    command_arn = f"arn:{partition}:iot:{ctx.region}:{ctx.account}:command/{command_id}"

    assert out["CommandRef"] == command_id, f"Ref {out['CommandRef']!r} != {command_id!r}"
    assert out["CommandArn"] == command_arn, f"GetAtt CommandArn {out['CommandArn']!r}"

    # Independent read: ListCommands by id, never a read keyed by the Ref.
    listed = [c["commandId"] for c in paginate(iot, "list_commands", "commands")
              if c["commandId"] == command_id]
    assert listed == [command_id], f"ListCommands found {listed!r} for {command_id!r}"

    got = iot.get_command(commandId=command_id)
    assert got["commandArn"] == command_arn, f"GetCommand arn {got['commandArn']!r}"
    assert got["namespace"] == "AWS-IoT", f"GetCommand namespace {got['namespace']!r}"
    assert got["displayName"] == display_name, f"GetCommand displayName {got['displayName']!r}"
    assert got["payload"]["content"] == content.encode(), (
        f"GetCommand payload content {got['payload']['content']!r}"
    )
    assert got["payload"]["contentType"] == "application/json", (
        f"GetCommand payload contentType {got['payload']['contentType']!r}"
    )
    assert (got["deprecated"], got["pendingDeletion"]) == (False, False), (
        f"GetCommand (deprecated, pendingDeletion) {(got['deprecated'], got['pendingDeletion'])!r}"
    )

    delete_stack(cf, stack_id)

    # DeleteCommand tombstones a not-yet-deprecated command instead of removing it outright: the
    # command stays readable, deprecated and pending deletion, rather than raising not-found.
    after = iot.get_command(commandId=command_id)
    assert (after["deprecated"], after["pendingDeletion"]) == (True, True), (
        f"after delete, (deprecated, pendingDeletion) {(after['deprecated'], after['pendingDeletion'])!r}"
    )
    assert after["commandArn"] == command_arn, f"after delete, GetCommand arn {after['commandArn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
