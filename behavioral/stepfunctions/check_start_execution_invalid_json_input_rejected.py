"""start-execution-invalid-json-input-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-invalid-json-input-rejected"
GROUP = 'errors'
SERVICES = ['stepfunctions']
_INVALID_INPUT_MESSAGE = (
    "Invalid State Machine Execution Input: 'Unrecognized token 'not': was expecting "
    "(JSON String, Number, Array, Object or token 'null', 'true' or 'false')'"
)


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role with no permissions; the state
    machines here call no AWS API."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine on a fresh role, retrying AccessDeniedException while it propagates.

    IAM exposes no condition to poll for a new role becoming assumable."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExecution with non-JSON input fails InvalidExecutionInput and creates no execution,
    while valid JSON input on the same state machine starts one (positive control)."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"ok": True}))

    good_name = ctx.unique_name("exec-goodinput-")
    good = sfn.start_execution(stateMachineArn=arn, name=good_name, input="{}")
    ctx.on_cleanup(lambda a=good["executionArn"]: sfn.stop_execution(executionArn=a))
    assert "executionArn" in good, f"expected the positive control to start, got {good}"

    bad_name = ctx.unique_name("exec-badinput-")
    error = _client_error(
        lambda: sfn.start_execution(stateMachineArn=arn, name=bad_name, input="not-json")
    )
    assert error.get("Code") == "InvalidExecutionInput", f"expected InvalidExecutionInput, got {error!r}"
    assert error.get("Message") == _INVALID_INPUT_MESSAGE, (
        f"expected InvalidExecutionInput message {_INVALID_INPUT_MESSAGE!r}, got {error.get('Message')!r}"
    )

    listed = sfn.list_executions(stateMachineArn=arn)["executions"]
    assert not any(e["name"] == bad_name for e in listed), (
        f"a rejected StartExecution must not create any execution: {listed}"
    )
    assert any(e["name"] == good_name for e in listed), (
        f"the positive control execution must be visible in list_executions: {listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
