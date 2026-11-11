"""deep-cloudformation-2-deployment-mode-express."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-2-deployment-mode-express"
GROUP = 'deploy'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_terminal(cf, stack_id, *, timeout_s=600, interval_s=3):
    """Poll DescribeStacks (by stack id) until the stack reaches a terminal state."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        last = stack["StackStatus"]
        if last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {last!r} after {timeout_s}s")
        time.sleep(interval_s)


def _resource_statuses(cf, stack_id):
    """Every (LogicalResourceId, ResourceStatus) pair in the stack's event history."""
    seen = set()
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for ev in page["StackEvents"]:
            seen.add((ev["LogicalResourceId"], ev["ResourceStatus"]))
    return seen


def _delete_param_quietly(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _delete_stack(cf, stack_id):
    try:
        cf.delete_stack(StackName=stack_id)
        _wait_terminal(cf, stack_id)
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id} teardown failed: {exc!r}") from exc


def _param_error(ssm, name):
    """('<present>', None) if the parameter exists, else GetParameter's error (code, message)."""
    try:
        ssm.get_parameter(Name=name)
        return "<present>", None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _wait_param_gone(ssm, name, *, timeout_s=60, interval_s=2):
    """GetParameter's (code, message) once the parameter is gone, or the last one at timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, msg = _param_error(ssm, name)
        if code == "ParameterNotFound" or time.monotonic() >= deadline:
            return code, msg
        time.sleep(interval_s)


def _template(name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "A": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name, "Type": "String", "Value": "resource-a"},
            },
            # Ref A resolves to A's Name: B depends on A and collides with it at runtime.
            "B": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": {"Ref": "A"}, "Type": "String", "Value": "resource-b"},
            },
        },
    })


def _failed_create(ctx, cf, ssm, label, deployment_config):
    stack_name = ctx.unique_name(f"sim2real-behav-dmode-{label}-")
    param = "/" + ctx.unique_name(f"sim2real-behav-dmode-{label}-")
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, param))
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(param),
        DeploymentConfig=deployment_config,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    stack = _wait_terminal(cf, stack_id)
    events = _resource_statuses(cf, stack_id)
    assert ("A", "CREATE_COMPLETE") in events, (
        f"[{label}] A must be created before B fails, or its fate proves nothing; "
        f"events={sorted(events)!r}"
    )
    assert ("B", "CREATE_FAILED") in events, (
        f"[{label}] B's designed runtime failure did not happen; events={sorted(events)!r}"
    )
    return stack, events, param


@tags("plane:control", "concern:deploy", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """EXPRESS leaves a failed create un-rolled-back; STANDARD and EXPRESS+DisableRollback=false
    roll it back and destroy the resource that had been created.

    One template runs in all three arms: B reuses A's Name, so it fails only after A exists.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    # Arm 1 -- EXPRESS, rollback left at its mode default (off).
    stack, events, express_param = _failed_create(ctx, cf, ssm, "express", {"Mode": "EXPRESS"})
    assert stack["StackStatus"] == "CREATE_FAILED", (
        f"EXPRESS: failed create must stop at CREATE_FAILED (no rollback); got "
        f"{stack['StackStatus']!r} ({stack.get('StackStatusReason')!r})"
    )
    assert stack.get("StackStatusReason") == (
        "The following resource(s) failed to create via Express Mode: [B]. "
    ), stack.get("StackStatusReason")
    dc = stack.get("DeploymentConfig") or {}
    assert dc.get("Mode") == "EXPRESS" and dc.get("DisableRollback") is True, (
        f"EXPRESS must resolve DisableRollback to its mode default True; DeploymentConfig={dc!r}"
    )
    assert ("A", "DELETE_COMPLETE") not in events, (
        f"EXPRESS: A must not be deleted by the failed create; events={sorted(events)!r}"
    )
    value = ssm.get_parameter(Name=express_param)["Parameter"]["Value"]
    assert value == "resource-a", f"EXPRESS: A must survive at SSM; GetParameter -> {value!r}"

    # Arm 2 -- STANDARD: the same failure rolls back and destroys A.
    stack, _, standard_param = _failed_create(ctx, cf, ssm, "standard", {"Mode": "STANDARD"})
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"STANDARD: failed create must roll back; got {stack['StackStatus']!r}"
    )
    assert stack.get("StackStatusReason") is None, stack.get("StackStatusReason")
    code, msg = _wait_param_gone(ssm, standard_param)
    assert code == "ParameterNotFound", (
        f"STANDARD: rollback must delete A; GetParameter -> {code!r}"
    )
    assert msg == "", f"STANDARD: GetParameter's ParameterNotFound message is {msg!r}"

    # Arm 3 -- EXPRESS with DisableRollback=false: rollback is re-enabled.
    stack, _, rb_param = _failed_create(
        ctx, cf, ssm, "exprb", {"Mode": "EXPRESS", "DisableRollback": False}
    )
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"EXPRESS+DisableRollback=false must roll back; got {stack['StackStatus']!r}"
    )
    dc = stack.get("DeploymentConfig") or {}
    assert dc.get("Mode") == "EXPRESS", f"arm 3 must still be EXPRESS; DeploymentConfig={dc!r}"
    assert stack.get("StackStatusReason") == (
        "Stack operation completed using Express Mode. Resources may continue becoming "
        "available in the background."
    ), stack.get("StackStatusReason")
    code, msg = _wait_param_gone(ssm, rb_param)
    assert code == "ParameterNotFound", (
        f"EXPRESS+DisableRollback=false: rollback must delete A; GetParameter -> {code!r}"
    )
    assert msg == "", f"EXPRESS+DisableRollback=false: ParameterNotFound message is {msg!r}"

    # The differential holds at the end: the EXPRESS arm's A is still alive.
    assert _param_error(ssm, express_param)[0] == "<present>", (
        "EXPRESS arm's A vanished after the other arms ran"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
