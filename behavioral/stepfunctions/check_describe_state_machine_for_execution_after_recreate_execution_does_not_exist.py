"""describe-state-machine-for-execution-after-recreate-execution-does-not-exist."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-for-execution-after-recreate-execution-does-not-exist"
GROUP = "environment-fidelity"
SERVICES = ["stepfunctions"]

_SFN_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_PASS_ASL = json.dumps({"StartAt": "Noop", "States": {"Noop": {"Type": "Pass", "End": True}}})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-dsmfe-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_SFN_TRUST,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_with_role_propagation(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _recreate_with_deleting_retry(sfn, *, deadline, **kwargs):
    """CreateStateMachine under a name whose previous incarnation may still be draining."""
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "StateMachineDeleting"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _delete_and_wait(sfn, arn: str, *, timeout_s: float = 240.0) -> None:
    """Delete, then poll until describe reports it gone. DeleteStateMachine is asynchronous."""
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "StateMachineDoesNotExist":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"{arn} still describes {timeout_s}s after DeleteStateMachine")


def _run_to_terminal(sfn, sm_arn: str, *, name: str, timeout_s: float = 30.0) -> str:
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, name=name, input="{}")["executionArn"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            assert last["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {last!r}"
            return exec_arn
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s (last={last!r})")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineForExecution on an execution ARN whose state machine was deleted and
    recreated under the same name answers ExecutionDoesNotExist, not the recreated machine's data.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _sfn_role(ctx)
    sm_name = ctx.unique_name("sim2real-sfn-dsmfe-")
    exec_name = ctx.unique_name("sim2real-sfn-dsmfe-exec-")

    first_arn = _create_with_role_propagation(
        sfn,
        name=sm_name,
        definition=_PASS_ASL,
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=first_arn)))

    old_exec_arn = _run_to_terminal(sfn, first_arn, name=exec_name)

    # Positive control: DescribeStateMachineForExecution works on a live execution.
    live = sfn.describe_state_machine_for_execution(executionArn=old_exec_arn)
    assert live["stateMachineArn"] == first_arn, (
        f"DescribeStateMachineForExecution on a live execution returned stateMachineArn "
        f"{live['stateMachineArn']!r}, expected {first_arn!r}"
    )
    assert live["definition"] == _PASS_ASL, (
        "DescribeStateMachineForExecution returned the wrong definition"
    )

    # Break exactly one thing: delete the machine, then recreate the identical name.
    _delete_and_wait(sfn, first_arn)
    deadline = time.monotonic() + 240.0
    new_arn = _recreate_with_deleting_retry(
        sfn,
        deadline=deadline,
        name=sm_name,
        definition=_PASS_ASL,
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    assert new_arn == first_arn, (
        f"the recreated machine's ARN {new_arn!r} differs from the original {first_arn!r}"
    )

    code, message = _error(
        lambda: sfn.describe_state_machine_for_execution(executionArn=old_exec_arn)
    )
    assert code == "ExecutionDoesNotExist", (
        f"DescribeStateMachineForExecution on the deleted machine's old execution {old_exec_arn!r} "
        f"returned {code!r}, not ExecutionDoesNotExist"
    )
    assert message == f"Execution Does Not Exist: '{old_exec_arn}'", (
        f"unexpected ExecutionDoesNotExist message {message!r}"
    )

    # Second positive control, in the same file: a FRESH execution reusing the same name on the
    # recreated machine is described correctly, so the rejection above is about the vanished
    # execution record, not a general DescribeStateMachineForExecution breakage.
    new_exec_arn = _run_to_terminal(sfn, new_arn, name=exec_name)
    ctx.on_cleanup(
        _teardown(lambda: sfn.stop_execution(executionArn=new_exec_arn), "ExecutionDoesNotExist")
    )
    assert new_exec_arn == old_exec_arn, (
        f"reusing execution name {exec_name!r} on the recreated machine produced {new_exec_arn!r}, "
        f"expected the same ARN {old_exec_arn!r}"
    )
    fresh = sfn.describe_state_machine_for_execution(executionArn=new_exec_arn)
    assert fresh["stateMachineArn"] == new_arn, (
        f"DescribeStateMachineForExecution on the fresh execution returned stateMachineArn "
        f"{fresh['stateMachineArn']!r}, expected {new_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
