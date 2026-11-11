"""get-execution-history-execution-not-exist."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-execution-history-execution-not-exist"
GROUP = 'execution_history'
SERVICES = ['stepfunctions']


def _role_arn(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
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
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING an executionArn real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _fake_execution_arn(state_machine_arn, suffix="never-existed"):
    """A syntactically well-formed but nonexistent executionArn derived from a real
    stateMachineArn so the account/region/partition segments are realistic."""
    return state_machine_arn.replace(":stateMachine:", ":execution:") + f":{suffix}-{uuid.uuid4().hex[:8]}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetExecutionHistory on a well-formed but never-created executionArn fails with
    ExecutionDoesNotExist and the exact message, while a real execution of the same state machine
    returns events."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
    arn = _create_state_machine(ctx, definition)

    real_exec_arn = _start_execution(ctx, arn)
    _wait_execution_complete(ctx, real_exec_arn)
    real_history = sfn.get_execution_history(executionArn=real_exec_arn)
    assert real_history["events"], f"expected events for a real execution, got {real_history['events']!r}"

    bogus = _fake_execution_arn(arn)
    code, message = _error_code(lambda: sfn.get_execution_history(executionArn=bogus))
    assert code == "ExecutionDoesNotExist", f"expected ExecutionDoesNotExist, got {code}"
    expected_message = f"Execution Does Not Exist: '{bogus}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
