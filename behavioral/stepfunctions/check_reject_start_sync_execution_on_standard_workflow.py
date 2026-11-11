"""reject-start-sync-execution-on-standard-workflow."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "reject-start-sync-execution-on-standard-workflow"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSyncExecution against a STANDARD (non-EXPRESS) state machine is
    rejected rather than silently falling back to an asynchronous execution."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-sfn-std-")
    definition = json.dumps(
        {"StartAt": "Pass1", "States": {"Pass1": {"Type": "Pass", "End": True}}}
    )
    create_resp = _create_state_machine_with_retry(
        ctx, name, definition, role_arn, type="STANDARD"
    )
    sm_arn = create_resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    code = message = None
    try:
        sfn.start_sync_execution(stateMachineArn=sm_arn, input="{}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")

    assert code is not None, "StartSyncExecution on a STANDARD workflow unexpectedly succeeded"
    assert code == "StateMachineTypeNotSupported", f"expected StateMachineTypeNotSupported, got {code}"
    expected = "This operation is not supported by this type of state machine"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The refusal must be real, not a rejection response wrapped around a silent async
    # fallback: an independent read proves the rejected call left no execution behind.
    executions_after_reject = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    assert executions_after_reject == [], (
        f"StartSyncExecution was refused but an execution exists anyway: {executions_after_reject!r}"
    )

    # Sanity: the same STANDARD state machine happily takes a normal async StartExecution.
    start_resp = sfn.start_execution(stateMachineArn=sm_arn, input="{}")
    exec_arn = start_resp["executionArn"]
    status = _wait_execution_terminal(ctx, exec_arn, timeout_s=30)
    assert status == "SUCCEEDED", f"expected async execution to succeed, got {status}"


def _create_sfn_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine_with_retry(
    ctx: Any, name: str, definition: str, role_arn: str, **kwargs: Any
) -> dict:
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, **kwargs
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_exc = e
                time.sleep(2)
                continue
            raise
    raise last_exc


def _wait_execution_terminal(
    ctx: Any, execution_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0
) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    status = "RUNNING"
    while time.monotonic() < deadline:
        status = sfn.describe_execution(executionArn=execution_arn)["status"]
        if status != "RUNNING":
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
