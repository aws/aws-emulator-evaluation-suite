"""list-executions-resource-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executions-resource-not-found"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


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
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListExecutions on a fully deleted state machine fails with StateMachineDoesNotExist and the exact
    message, not the ResourceNotFound that ListExecutions uses for a nonexistent mapRunArn."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
    arn = _create_state_machine(ctx, definition)
    sfn.delete_state_machine(stateMachineArn=arn)

    deadline = time.monotonic() + 270
    gone = False
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "StateMachineDoesNotExist":
                gone = True
                break
        time.sleep(5)
    assert gone, "state machine was not fully removed before exercising ListExecutions on it"

    code, message = _error(lambda: sfn.list_executions(stateMachineArn=arn))
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code}"
    assert message == f"State Machine Does Not Exist: '{arn}'", f"unexpected StateMachineDoesNotExist message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
