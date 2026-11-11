"""describe-state-machine-for-execution-not-exist."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-for-execution-not-exist"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fake_execution_arn(state_machine_arn, suffix="never-existed"):
    """A syntactically well-formed but nonexistent executionArn, derived from a real
    stateMachineArn so the account/region/partition segments are realistic."""
    return state_machine_arn.replace(":stateMachine:", ":execution:") + f":{suffix}-{uuid.uuid4().hex[:8]}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineForExecution on a well-formed but never-created executionArn fails with
    ExecutionDoesNotExist and the exact message, while a real execution returns its state machine ARN."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass(), _create_sfn_role(ctx))

    real_exec_arn = _start_execution(ctx, arn)
    positive = sfn.describe_state_machine_for_execution(executionArn=real_exec_arn)
    assert positive["stateMachineArn"] == arn, (
        f"positive control: expected stateMachineArn == {arn}, got {positive}"
    )

    bogus = _fake_execution_arn(arn)
    code, message = _error(lambda: sfn.describe_state_machine_for_execution(executionArn=bogus))
    assert code == "ExecutionDoesNotExist", f"expected ExecutionDoesNotExist, got {code}"
    expected = f"Execution Does Not Exist: '{bogus}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
