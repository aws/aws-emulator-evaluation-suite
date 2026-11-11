"""stop-execution-not-exist."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-execution-not-exist"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    The state machines here call no AWS API on the customer's behalf, so the role carries no
    permissions. It is created rather than looked up because a role the check did not create
    is account configuration, not a service contract.
    """
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


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine on a fresh role, retrying the one error IAM propagation can produce.

    A freshly created role is not instantly assumable and IAM exposes no condition to poll
    for that, so the bounded AccessDeniedException retry is the wait.
    """
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
                tags=[{"key": "sim2real", "value": "1"}],
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
    """The botocore Error dict `fn` raises. An unexpected SUCCESS raises AssertionError, so a
    target accepting a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


# StopExecution is a no-op on a terminal execution; these codes mean already deleted.
_GONE_CODES = ("ExecutionDoesNotExist", "StateMachineDoesNotExist", "NoSuchEntity")


def _ignore_gone(fn):
    """Run a teardown call; only a resource that is already gone is not an error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _fake_execution_arn(state_machine_arn, suffix="never-existed"):
    """A syntactically well-formed but nonexistent executionArn derived from a real
    stateMachineArn so the account/region/partition segments are realistic."""
    return state_machine_arn.replace(":stateMachine:", ":execution:") + f":{suffix}-{uuid.uuid4().hex[:8]}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopExecution on a well-formed but never-created executionArn -> ExecutionDoesNotExist,
    after a positive control proves a real running execution stops and reads back ABORTED."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Wait", "States": {"Wait": {"Type": "Wait", "Seconds": 60, "End": True}}}
    arn = _create_state_machine(ctx, definition)

    real_exec_arn = sfn.start_execution(
        stateMachineArn=arn, name=ctx.unique_name("sim2real-behav-exec-")
    )["executionArn"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: sfn.stop_execution(executionArn=real_exec_arn)))

    sfn.stop_execution(executionArn=real_exec_arn)
    status = sfn.describe_execution(executionArn=real_exec_arn)["status"]
    assert status == "ABORTED", f"expected the real execution to read back ABORTED, got {status}"

    bogus = _fake_execution_arn(arn)
    error = _client_error(lambda: sfn.stop_execution(executionArn=bogus))
    assert error.get("Code") == "ExecutionDoesNotExist", f"expected ExecutionDoesNotExist, got {error!r}"
    expected_message = f"Execution Does Not Exist: '{bogus}'"
    assert error.get("Message") == expected_message, (
        f"expected ExecutionDoesNotExist message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
