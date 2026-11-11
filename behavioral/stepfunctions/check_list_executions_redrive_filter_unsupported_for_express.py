"""list-executions-redrive-filter-unsupported-for-express."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executions-redrive-filter-unsupported-for-express"
GROUP = 'errors'
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
    """ListExecutions on an EXPRESS state machine is rejected with StateMachineTypeNotSupported,
    since EXPRESS keeps no execution history; redriveFilter with any stateMachineArn is a
    separate ValidationException, identical on STANDARD and EXPRESS (it needs a mapRunArn)."""
    sfn = ctx.client("stepfunctions")

    std_arn = _create_state_machine(ctx, _asl_pass({"ok": True}), sm_type="STANDARD")
    control = sfn.list_executions(stateMachineArn=std_arn)
    assert control.get("executions") == [], (
        f"expected an empty execution list for a fresh STANDARD state machine, got {control}"
    )

    express_arn = _create_state_machine(ctx, _asl_pass({"ok": True}), sm_type="EXPRESS")
    express_code, express_message = _error(lambda: sfn.list_executions(stateMachineArn=express_arn))
    assert express_code == "StateMachineTypeNotSupported", (
        "expected StateMachineTypeNotSupported listing executions of an EXPRESS state "
        f"machine (no redriveFilter involved), got {express_code}"
    )
    assert express_message == "This operation is not supported by this type of state machine", (
        f"unexpected StateMachineTypeNotSupported message {express_message!r}"
    )

    for label, arn in (("STANDARD", std_arn), ("EXPRESS", express_arn)):
        code, message = _error(
            lambda arn=arn: sfn.list_executions(stateMachineArn=arn, redriveFilter="NOT_REDRIVEN")
        )
        assert code == "ValidationException", (
            f"expected ValidationException combining redriveFilter with a stateMachineArn "
            f"on {label}, got {code}"
        )
        assert message == "RedriveFilter cannot be applied to ListExecutions call with StateMachine ARN", (
            f"unexpected RedriveFilter validation message on {label}: {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
