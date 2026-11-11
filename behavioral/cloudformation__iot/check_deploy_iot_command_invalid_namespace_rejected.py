"""deploy-iot-command-invalid-namespace-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iot-command-invalid-namespace-rejected"
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

def _template(command_id, namespace, content):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Command": {
                "Type": "AWS::IoT::Command",
                "Properties": {
                    "CommandId": command_id,
                    "Namespace": namespace,
                    "Payload": {"Content": content, "ContentType": "application/json"},
                },
            },
        },
        "Outputs": {"CommandRef": {"Value": {"Ref": "Command"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation IoT command with an invalid Namespace fails early validation and rolls back.

    IoT lists no command under the id, while the same template with Namespace AWS-IoT deploys a
    command that reads back with its payload.
    """
    cf = ctx.client("cloudformation")
    iot = ctx.client("iot")
    good_id = ctx.unique_name("sim2realcfniotcmdgood")
    bad_id = ctx.unique_name("sim2realcfniotcmdbad")
    content = base64.b64encode(json.dumps({"action": "sim2real-noop"}).encode()).decode()

    # Positive control: same template, the one property given a VALID value (never dropped).
    good_stack = ctx.unique_name("sim2real-cfniotcmdneg-good-")
    good_id_stack = create_stack(ctx, cf, good_stack, _template(good_id, "AWS-IoT", content))
    status = wait_stack(cf, good_id_stack)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    ref = stack_outputs(cf, good_id_stack)["CommandRef"]
    listed = [c["commandId"] for c in paginate(iot, "list_commands", "commands")
              if c["commandId"] == good_id]
    assert listed == [ref], f"control ListCommands {listed!r} for Ref {ref!r}"
    got = iot.get_command(commandId=good_id)
    assert (got["namespace"], got["payload"]["content"], got["payload"]["contentType"]) == (
        "AWS-IoT", base64.b64decode(content), "application/json"), f"control command {got!r}"

    bad_namespace = f"{good_id[:9]}-BOGUS"
    bad_stack = ctx.unique_name("sim2real-cfniotcmdneg-bad-")
    bad_id_stack = create_stack(ctx, cf, bad_stack, _template(bad_id, bad_namespace, content))
    status = wait_stack(cf, bad_id_stack)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id_stack)
    want = [(
        "Command", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"{bad_namespace} is not a valid enum value. Supported values: [AWS-IoT, "
        "AWS-IoT-FleetWise]",
        "/Resources/Command/Properties/Namespace",
    )]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Rollback absence through IoT, by the id the command would have, BEFORE this check deletes.
    listed = [c["commandId"] for c in paginate(iot, "list_commands", "commands")
              if c["commandId"] == bad_id]
    assert listed == [], f"the rolled-back command is listed: {listed!r}"
    gone = ("ResourceNotFoundException", f"Command {bad_id} cannot be found.")
    expect_error(lambda: iot.get_command(commandId=bad_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
