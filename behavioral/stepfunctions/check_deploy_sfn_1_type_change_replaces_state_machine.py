"""deploy-sfn-1-type-change-replaces-state-machine."""
from __future__ import annotations

import json
import sys
import time

from behavioral_harness import tags

CHECK = "deploy-sfn-1-type-change-replaces-state-machine"
GROUP = "deploy-stack"
SERVICES = ["stepfunctions"]

_STATE_MACHINE = "Workflow"
_MODE = "deploy"
_TARGET = "Greet"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN state machine runs with its DefinitionSubstitutions resolved; a StateMachineType change
    replaces it with a new EXPRESS ARN that runs synchronously, and the old ARN no longer exists.
    """
    cfn = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")
    stack_name = ctx.unique_name("sim2real-sfn-deploy-")
    token = ctx.unique_name("tok-")
    substitutions = {"TargetName": _TARGET, "ModeValue": _MODE, "RunToken": token}
    expected = {
        "mode": _MODE,
        "result": {"routedTo": _TARGET, "mode": _MODE, "token": token, "banner": f"run={token}"},
    }

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template("STANDARD", substitutions),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_or_leak(cfn, stack_id))

    status = _wait_stack_terminal(cfn, stack_id, "CREATE_IN_PROGRESS")
    assert status == "CREATE_COMPLETE", (
        f"stack create ended {status!r}, expected 'CREATE_COMPLETE'; "
        f"failed events: {_failed_events(cfn, stack_id)!r}"
    )
    old_arn = _output(cfn, stack_id, "StateMachineArn")
    old_physical = _physical_id(cfn, stack_id)
    assert old_physical == old_arn, (
        f"physical id {old_physical!r} != Ref output {old_arn!r} for the state machine"
    )
    old_desc = sfn.describe_state_machine(stateMachineArn=old_arn)
    assert old_desc["type"] == "STANDARD", f"deployed type was {old_desc['type']!r}, expected 'STANDARD'"
    assert "${" not in old_desc["definition"], (
        f"deployed definition still carries a placeholder: {old_desc['definition']!r}"
    )

    # Positive control for the later negative: the OLD ARN executes and returns the resolved output.
    exec_arn = sfn.start_execution(stateMachineArn=old_arn, input=json.dumps({"mode": _MODE}))["executionArn"]
    done = _poll(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        what=f"execution {exec_arn} to leave RUNNING",
    )
    assert done["status"] == "SUCCEEDED", (
        f"STANDARD execution ended {done['status']!r} (error={done.get('error')!r}, "
        f"cause={done.get('cause')!r}), expected 'SUCCEEDED'"
    )
    assert "${" not in done["output"], f"execution output carries an unresolved placeholder: {done['output']!r}"
    assert json.loads(done["output"]) == expected, (
        f"STANDARD execution output {done['output']!r}, expected {expected!r}"
    )

    # Change ONLY StateMachineType. No StateMachineName is set, so CFN must replace the resource.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template("EXPRESS", substitutions),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    status = _wait_stack_terminal(cfn, stack_id, "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS")
    assert status == "UPDATE_COMPLETE", (
        f"stack update ended {status!r}, expected 'UPDATE_COMPLETE'; "
        f"failed events: {_failed_events(cfn, stack_id)!r}"
    )
    new_arn = _output(cfn, stack_id, "StateMachineArn")
    new_physical = _physical_id(cfn, stack_id)
    assert new_physical == new_arn, f"physical id {new_physical!r} != Ref output {new_arn!r} after update"
    assert new_arn != old_arn, (
        f"StateMachineType change kept the same ARN {old_arn!r}; it must replace the resource"
    )
    new_desc = sfn.describe_state_machine(stateMachineArn=new_arn)
    assert new_desc["type"] == "EXPRESS", f"replacement type was {new_desc['type']!r}, expected 'EXPRESS'"

    # The old resource is deleted by the update's cleanup phase. Deletion is asynchronous, so poll
    # the observable status until the ARN stops resolving, then assert the exact code.
    gone, gone_message = _wait_absent(sfn, old_arn)
    assert gone == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on the replaced ARN raised {gone!r}, expected 'StateMachineDoesNotExist'"
    )
    gone_expected = f"State Machine Does Not Exist: '{old_arn}'"
    assert gone_message == gone_expected, f"expected message {gone_expected!r}, got {gone_message!r}"
    start_code, start_message = _error(lambda: sfn.start_execution(stateMachineArn=old_arn, input="{}"))
    assert start_code == "StateMachineDoesNotExist", (
        f"StartExecution on the replaced ARN raised {start_code!r}, expected 'StateMachineDoesNotExist'"
    )
    assert start_message == gone_expected, f"expected message {gone_expected!r}, got {start_message!r}"

    sync = sfn.start_sync_execution(stateMachineArn=new_arn, input=json.dumps({"mode": _MODE}))
    assert sync["status"] == "SUCCEEDED", (
        f"StartSyncExecution on the EXPRESS replacement ended {sync['status']!r} "
        f"(error={sync.get('error')!r}, cause={sync.get('cause')!r}), expected 'SUCCEEDED'"
    )
    assert "${" not in sync["output"], f"sync output carries an unresolved placeholder: {sync['output']!r}"
    assert json.loads(sync["output"]) == expected, (
        f"EXPRESS sync output {sync['output']!r}, expected {expected!r}"
    )

    # Teardown is part of the contract: the stack reaches DELETE_COMPLETE and takes the state
    # machine with it. The registered cleanup is the net for an earlier failure, not this path.
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack_terminal(cfn, stack_id, "DELETE_IN_PROGRESS")
    assert status == "DELETE_COMPLETE", (
        f"stack delete ended {status!r}, expected 'DELETE_COMPLETE'; "
        f"failed events: {_failed_events(cfn, stack_id)!r}"
    )
    gone, gone_message = _wait_absent(sfn, new_arn)
    assert gone == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on the deleted stack's state machine raised {gone!r}, "
        "expected 'StateMachineDoesNotExist'"
    )
    gone_expected = f"State Machine Does Not Exist: '{new_arn}'"
    assert gone_message == gone_expected, f"expected message {gone_expected!r}, got {gone_message!r}"


def _template(sm_type: str, substitutions: dict) -> str:
    definition = {
        "Comment": "sim2real deploy-stack substitution probe",
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.mode", "StringEquals": "${ModeValue}", "Next": "${TargetName}"}],
                "Default": "NoRoute",
            },
            _TARGET: {
                "Type": "Pass",
                "Result": {
                    "routedTo": "${TargetName}",
                    "mode": "${ModeValue}",
                    "token": "${RunToken}",
                    "banner": "run=${RunToken}",
                },
                "ResultPath": "$.result",
                "End": True,
            },
            "NoRoute": {"Type": "Fail", "Error": "NoRoute", "Cause": "Choice fell through to Default"},
        },
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            _STATE_MACHINE: {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineType": sm_type,
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Definition": definition,
                    "DefinitionSubstitutions": substitutions,
                },
            },
        },
        "Outputs": {"StateMachineArn": {"Value": {"Ref": _STATE_MACHINE}}},
    })


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _wait_stack_terminal(cfn, stack_id: str, *transient: str, timeout_s: float = 600.0) -> str:
    st = _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s not in transient,
        timeout_s=timeout_s,
        interval_s=5.0,
        what=f"stack {stack_id} to leave {transient!r}",
    )
    return st


def _output(cfn, stack_id: str, key: str) -> str:
    outs = {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}
    assert key in outs, f"stack output {key!r} missing; outputs were {outs!r}"
    return outs[key]


def _physical_id(cfn, stack_id: str) -> str:
    res = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=_STATE_MACHINE)
    return res["StackResourceDetail"]["PhysicalResourceId"]


def _failed_events(cfn, stack_id: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for e in page["StackEvents"]:
            if e["ResourceStatus"].endswith("_FAILED"):
                out.append((e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason")))
    return out


def _wait_absent(sfn, arn: str, timeout_s: float = 180.0) -> tuple:
    """Poll DescribeStateMachine until it raises; return the (code, message) it raised.

    Any error ends the poll, so the caller's exact-code assertion sees a wrong code unretried.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = sfn.describe_state_machine(stateMachineArn=arn).get("status")
        except sfn.exceptions.ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(3.0)
    raise AssertionError(f"{arn} still resolves after {timeout_s}s (last status={last!r})")


def _error(fn) -> tuple:
    """Call fn(); return the (code, message) of the AWS error it raises, or raise if it succeeds."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — botocore ClientError carries the code
        resp = getattr(exc, "response", None)
        if resp is None:
            raise
        return resp["Error"]["Code"], resp["Error"].get("Message")
    raise AssertionError("call unexpectedly SUCCEEDED; expected it to be rejected")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what} (last={last!r})")


def _delete_stack_or_leak(cfn, stack_id: str) -> None:
    """Delete a stack left by an earlier failure; raise naming the stack if it does not delete.

    Deleting by stack ID is idempotent: a no-op on a stack already DELETE_COMPLETE.
    """
    try:
        cfn.delete_stack(StackName=stack_id)
        status = _wait_stack_terminal(cfn, stack_id, "DELETE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS",
                                      "UPDATE_ROLLBACK_IN_PROGRESS",
                                      "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
                                      "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS")
        if status != "DELETE_COMPLETE":
            cfn.delete_stack(StackName=stack_id)
            status = _wait_stack_terminal(cfn, stack_id, "DELETE_IN_PROGRESS")
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack ended {status!r}, not 'DELETE_COMPLETE'")
    except Exception as exc:
        raise RuntimeError(f"cloudformation stack {stack_id}: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
