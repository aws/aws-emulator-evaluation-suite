"""create-state-machine-already-exists-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-already-exists-conflict"
GROUP = 'state_machine_lifecycle'
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


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an ACTIVE state machine's name with a DIFFERENT definition
    must fail StateMachineAlreadyExists, not silently succeed.
    """
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-conflict-")
    role_arn = _execution_role_arn(ctx)
    arn = _create_state_machine(ctx, _asl_pass({"v": 1}), name=name)

    code, message = _error(
        lambda: sfn.create_state_machine(
            name=name,
            definition=json.dumps(_asl_pass({"v": 2})),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": "1"}],
        )
    )
    assert code == "StateMachineAlreadyExists", f"expected StateMachineAlreadyExists, got {code}"
    assert message == f"State Machine Already Exists: '{arn}'", (
        f"unexpected StateMachineAlreadyExists message {message!r}"
    )

    # Independent read at the destination (DescribeStateMachine, not the mutating
    # CreateStateMachine call): the rejected duplicate must not have touched the original.
    live_definition = json.loads(sfn.describe_state_machine(stateMachineArn=arn)["definition"])
    assert live_definition == _asl_pass({"v": 1}), (
        f"original definition must be unchanged after a rejected duplicate create, got {live_definition}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
