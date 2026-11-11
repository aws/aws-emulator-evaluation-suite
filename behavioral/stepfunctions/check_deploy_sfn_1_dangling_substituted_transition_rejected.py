"""deploy-sfn-1-dangling-substituted-transition-rejected."""
from __future__ import annotations

import json
import sys
import time

from behavioral_harness import tags

CHECK = "deploy-sfn-1-dangling-substituted-transition-rejected"
GROUP = "deploy-stack"
SERVICES = ["stepfunctions"]

_STATE_MACHINE = "Workflow"
_TARGET = "Greet"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A DefinitionSubstitutions value that routes a Choice to a missing state rolls the stack back
    and leaves no state machine, while the same template routed to a real state deploys and runs.
    """
    # The inline Definition is valid as written; it only dangles once CloudFormation substitutes.
    cfn = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")
    good_stack = ctx.unique_name("sim2real-sfn-subok-")
    bad_stack = ctx.unique_name("sim2real-sfn-subbad-")
    good_sm = ctx.unique_name("sim2real-sfn-subok-sm-")
    bad_sm = ctx.unique_name("sim2real-sfn-subbad-sm-")

    good_id = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_sm, _TARGET),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_or_leak(cfn, good_id))

    bad_id = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_sm, "Nowhere"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_or_leak(cfn, bad_id))

    # Positive control: the same template, with the substitution naming a real state.
    status = _wait_stack_terminal(cfn, good_id, "CREATE_IN_PROGRESS")
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}, expected 'CREATE_COMPLETE'; "
        f"failed events: {_failed_events(cfn, good_id)!r}"
    )
    good_arn = _output(cfn, good_id, "StateMachineArn")
    exec_arn = sfn.start_execution(stateMachineArn=good_arn, input=json.dumps({"go": True}))["executionArn"]
    done = _poll(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        what=f"execution {exec_arn} to leave RUNNING",
    )
    assert done["status"] == "SUCCEEDED", (
        f"control execution ended {done['status']!r} (error={done.get('error')!r}), expected 'SUCCEEDED'"
    )
    assert json.loads(done["output"]) == {"go": True, "result": {"routedTo": _TARGET}}, (
        f"control execution output {done['output']!r} does not show the substituted route"
    )

    # The broken stack: rejected at deploy time and rolled back.
    status = _wait_stack_terminal(cfn, bad_id, "CREATE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS")
    assert status == "ROLLBACK_COMPLETE", (
        f"stack whose substitution names a missing state ended {status!r}, expected 'ROLLBACK_COMPLETE'"
    )
    sm_statuses = [s for (lid, s, _r) in _events(cfn, bad_id) if lid == _STATE_MACHINE]
    assert "CREATE_FAILED" in sm_statuses, (
        f"state machine resource events were {sm_statuses!r}; expected a CREATE_FAILED"
    )
    assert "CREATE_COMPLETE" not in sm_statuses, (
        f"state machine resource reached CREATE_COMPLETE despite a dangling Next: {sm_statuses!r}"
    )

    # Effect absent: nothing exists under the broken stack's state-machine name. The ARN is the
    # control's ARN with only the resource-name segment swapped (same partition/region/account).
    prefix, _, _name = good_arn.rpartition(":")
    bad_arn = f"{prefix}:{bad_sm}"
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_arn))
    assert code == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on {bad_arn!r} raised {code!r}, expected 'StateMachineDoesNotExist'"
    )
    expected = f"State Machine Does Not Exist: '{bad_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    listed = [
        sm["name"]
        for page in sfn.get_paginator("list_state_machines").paginate()
        for sm in page["stateMachines"]
        if sm["name"] == bad_sm
    ]
    assert listed == [], f"ListStateMachines still shows the rejected state machine: {listed!r}"

    # Teardown is part of the contract for both stacks.
    for sid in (bad_id, good_id):
        cfn.delete_stack(StackName=sid)
    for sid in (bad_id, good_id):
        status = _wait_stack_terminal(cfn, sid, "DELETE_IN_PROGRESS")
        assert status == "DELETE_COMPLETE", (
            f"stack {sid} delete ended {status!r}, expected 'DELETE_COMPLETE'"
        )


def _template(sm_name: str, target: str) -> str:
    definition = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.go", "BooleanEquals": True, "Next": "${TargetName}"}],
                "Default": "NoRoute",
            },
            _TARGET: {
                "Type": "Pass",
                "Result": {"routedTo": "${TargetName}"},
                "ResultPath": "$.result",
                "End": True,
            },
            "NoRoute": {"Type": "Fail", "Error": "NoRoute"},
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
                    "StateMachineName": sm_name,
                    "StateMachineType": "STANDARD",
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Definition": definition,
                    "DefinitionSubstitutions": {"TargetName": target},
                },
            },
        },
        "Outputs": {"StateMachineArn": {"Value": {"Ref": _STATE_MACHINE}}},
    })


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _wait_stack_terminal(cfn, stack_id: str, *transient: str, timeout_s: float = 600.0) -> str:
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s not in transient,
        timeout_s=timeout_s,
        interval_s=5.0,
        what=f"stack {stack_id} to leave {transient!r}",
    )


def _output(cfn, stack_id: str, key: str) -> str:
    outs = {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}
    assert key in outs, f"stack output {key!r} missing; outputs were {outs!r}"
    return outs[key]


def _events(cfn, stack_id: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for e in page["StackEvents"]:
            out.append((e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason")))
    return out


def _failed_events(cfn, stack_id: str) -> list:
    return [e for e in _events(cfn, stack_id) if e[1].endswith("_FAILED")]


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
        status = _wait_stack_terminal(cfn, stack_id, "DELETE_IN_PROGRESS", "CREATE_IN_PROGRESS",
                                      "ROLLBACK_IN_PROGRESS")
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
