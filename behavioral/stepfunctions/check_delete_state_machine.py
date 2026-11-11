"""delete-state-machine."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-state-machine"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


def _poll_refusal(fn, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Call fn() until it is refused; return the refusal's (code, message). A describe that
    still succeeds mid-deletion is an expected transient, so only the deadline fails this."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")
        time.sleep(interval_s)


def _error(fn):
    """One-shot negative check: return the error (code, message). An unexpected SUCCESS here means a
    mutation on an already-deleted state machine went through."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the deleted state machine to reject this call, but it succeeded: {result!r}")


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteStateMachine, Describe eventually returns StateMachineDoesNotExist, and a
    further mutation against the dead ARN is rejected with the same code."""
    sfn = ctx.client("stepfunctions")
    definition = {
        "StartAt": "Pass",
        "States": {"Pass": {"Type": "Pass", "End": True}},
    }
    arn = _create_state_machine(ctx, definition)

    # Positive control: the state machine is live and describable before deletion.
    pre = sfn.describe_state_machine(stateMachineArn=arn)
    assert pre.get("status") == "ACTIVE", f"expected ACTIVE before delete, got {pre.get('status')!r}"

    sfn.delete_state_machine(stateMachineArn=arn)
    # resource deleted by the check; cleanup is idempotent/best-effort
    # DeleteStateMachine is asynchronous: the SM lingers in DELETING and remains
    # describable for a window that can exceed a minute on real AWS before it
    # finally returns StateMachineDoesNotExist. DELETING is a transient state and
    # must not be accepted as proof of deletion — poll past the window for the
    # terminal not-found code.
    code, message = _poll_refusal(
        lambda: sfn.describe_state_machine(stateMachineArn=arn),
        timeout_s=180,
        interval_s=2.0,
        description="state machine fully deleted",
    )
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code!r}"
    assert message == f"State Machine Does Not Exist: '{arn}'", (
        f"unexpected StateMachineDoesNotExist message {message!r}"
    )

    # A mutation against the now-dead ARN must fail with the same not-found code.
    update_code, update_message = _error(
        lambda: sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(definition))
    )
    assert update_code == "StateMachineDoesNotExist", (
        f"expected UpdateStateMachine on a deleted SM to fail with StateMachineDoesNotExist, got {update_code!r}"
    )
    assert update_message == f"State Machine Does Not Exist: '{arn}'", (
        f"unexpected UpdateStateMachine StateMachineDoesNotExist message {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
