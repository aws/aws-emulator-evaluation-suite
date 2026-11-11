"""deep-cloudformation-2-retain-except-on-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-2-retain-except-on-create"
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


def _client_error(fn):
    """Return the AWS error (code, message) `fn` raises; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly succeeded: {result!r}")


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


def _wait_param_gone(ssm, name, *, timeout_s=60, interval_s=2):
    """Poll GetParameter until ParameterNotFound; return the last (code, message) seen."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, msg = "<present>", None
        try:
            ssm.get_parameter(Name=name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, msg = err.get("Code"), err.get("Message")
        if code == "ParameterNotFound" or time.monotonic() >= deadline:
            return code, msg
        time.sleep(interval_s)


def _template(name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "A": {
                "Type": "AWS::SSM::Parameter",
                "DeletionPolicy": "Retain",
                "Properties": {"Name": name, "Type": "String", "Value": "resource-a"},
            },
            # Ref A resolves to A's Name, so B depends on A and collides with it at runtime:
            # B fails only after A is CREATE_COMPLETE, and pre-deployment validation cannot see it.
            "B": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": {"Ref": "A"}, "Type": "String", "Value": "resource-b"},
            },
        },
    })


def _create_and_roll_back(ctx, cf, ssm, label, **extra):
    stack_name = ctx.unique_name(f"sim2real-behav-reoc-{label}-")
    param = "/" + ctx.unique_name(f"sim2real-behav-reoc-{label}-")
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, param))
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(param),
        Tags=[{"Key": "sim2real", "Value": CHECK}], **extra,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    stack = _wait_terminal(cf, stack_id)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"[{label}] failed create should roll back; stack is {stack['StackStatus']!r} "
        f"({stack.get('StackStatusReason')!r})"
    )
    assert stack.get("StackStatusReason") is None, (
        f"[{label}] ROLLBACK_COMPLETE carries reason {stack.get('StackStatusReason')!r}"
    )
    events = _resource_statuses(cf, stack_id)
    assert ("A", "CREATE_COMPLETE") in events, (
        f"[{label}] A must be created before the rollback, or its absence proves nothing; "
        f"events={sorted(events)!r}"
    )
    assert ("B", "CREATE_FAILED") in events, (
        f"[{label}] the rollback must be caused by B's designed failure; events={sorted(events)!r}"
    )
    return param


@tags("plane:control", "concern:deploy", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """A DeletionPolicy:Retain resource outlives a create rollback by default, and is deleted by
    the same rollback when the stack was created with RetainExceptOnCreate=true."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    # Arm 1 -- DeletionPolicy:Retain alone: rollback must skip A, so A is alive at SSM.
    kept = _create_and_roll_back(ctx, cf, ssm, "retain")
    value = ssm.get_parameter(Name=kept)["Parameter"]["Value"]
    assert value == "resource-a", (
        f"Retain arm: A must survive the rollback with its own value; GetParameter -> {value!r}"
    )

    # Arm 2 -- the identical template plus RetainExceptOnCreate=true: A was newly created by
    # this operation, so the rollback must delete it despite DeletionPolicy:Retain.
    dropped = _create_and_roll_back(ctx, cf, ssm, "except", RetainExceptOnCreate=True)
    code, msg = _wait_param_gone(ssm, dropped)
    assert code == "ParameterNotFound", (
        f"RetainExceptOnCreate arm: A must be deleted by the rollback; GetParameter -> {code!r}"
    )
    assert msg == "", f"RetainExceptOnCreate arm: ParameterNotFound message is {msg!r}"
    recheck, recheck_msg = _client_error(lambda: ssm.get_parameter(Name=dropped))
    assert recheck == "ParameterNotFound", (
        f"RetainExceptOnCreate arm: A reappeared after deletion; GetParameter -> {recheck!r}"
    )
    assert recheck_msg == "", f"RetainExceptOnCreate arm: recheck message is {recheck_msg!r}"

    # The differential holds at the end: the Retain arm's A is still alive after arm 2 ran.
    still = ssm.get_parameter(Name=kept)["Parameter"]["Value"]
    assert still == "resource-a", f"Retain arm's A changed or vanished: {still!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
