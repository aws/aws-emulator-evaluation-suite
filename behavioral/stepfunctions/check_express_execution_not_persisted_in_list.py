"""express-execution-not-persisted-in-list."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "express-execution-not-persisted-in-list"
GROUP = "server-side"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSyncExecution on an EXPRESS machine returns SUCCEEDED with output, while ListExecutions
    on it raises StateMachineTypeNotSupported; a STANDARD machine's execution is listed.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_basic_execution_role(ctx)

    definition = json.dumps(
        {
            "StartAt": "Echo",
            "States": {
                "Echo": {
                    "Type": "Pass",
                    "Result": {"handled": True},
                    "ResultPath": "$.echo",
                    "End": True,
                }
            },
        }
    )
    sm_arn = _create_state_machine(ctx, definition, role_arn, "EXPRESS")

    described = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert described["type"] == "EXPRESS", described

    sync_resp = sfn.start_sync_execution(
        stateMachineArn=sm_arn, input=json.dumps({"orig": "x"})
    )
    assert sync_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {sync_resp}"
    output = json.loads(sync_resp["output"])
    assert output == {"orig": "x", "echo": {"handled": True}}, output

    # A STANDARD state machine's executions ARE listable - contrast case.
    standard_arn = _create_state_machine(ctx, definition, role_arn, "STANDARD")
    exec_arn = sfn.start_execution(stateMachineArn=standard_arn, input="{}")["executionArn"]
    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30,
    )
    standard_listed = sfn.list_executions(stateMachineArn=standard_arn)["executions"]
    assert any(e["executionArn"] == exec_arn for e in standard_listed), (
        "STANDARD executions must be listable via ListExecutions"
    )

    # ListExecutions against the EXPRESS state machine must be rejected outright.
    code, message = _error_code(lambda: sfn.list_executions(stateMachineArn=sm_arn))
    assert code == "StateMachineTypeNotSupported", (
        f"expected StateMachineTypeNotSupported for ListExecutions on EXPRESS, got {code}"
    )
    expected_message = "This operation is not supported by this type of state machine"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_basic_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition: str, role_arn: str, sm_type: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(f"sim2real-behav-sm-{sm_type.lower()}-")
    last_error = None
    for _ in range(15):
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type=sm_type
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except Exception as exc:  # noqa: BLE001 - retry on IAM role propagation delay
            last_error = exc
            time.sleep(2)
    raise AssertionError(f"could not create state machine (role propagation?): {last_error}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {result}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
