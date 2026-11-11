"""reject-redrive-nonexistent-execution."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "reject-redrive-nonexistent-execution"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on an execution ARN that never existed fails ExecutionDoesNotExist.

    A real failed execution is redriven first, so the rejection is specific to the missing ARN."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    role_arn = _create_basic_execution_role(ctx)
    activity_arn = _create_activity(ctx)

    definition = json.dumps(
        {
            "StartAt": "DoWork",
            "States": {"DoWork": {"Type": "Task", "Resource": activity_arn, "End": True}},
        }
    )
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("exec-"), input=json.dumps({})
    )["executionArn"]

    token = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=token, error="ProbeError", cause="induced failure")

    failed = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
    )
    assert failed["status"] == "FAILED", f"expected FAILED, got {failed['status']}"

    sfn.redrive_execution(executionArn=exec_arn)
    resumed = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] == "RUNNING",
        timeout_s=30,
    )
    assert resumed["status"] == "RUNNING", f"expected RUNNING after redrive, got {resumed}"

    token2 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=token2, output=json.dumps({"done": True}))
    succeeded = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
    )
    assert succeeded["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {succeeded}"
    assert succeeded["redriveCount"] == 1, f"expected redriveCount 1, got {succeeded.get('redriveCount')}"

    # Derived from a real ARN: a wholly fabricated one can fall outside the caller's resource
    # scope and surface AccessDeniedException instead of not-found.
    fake_execution_arn = exec_arn + "-neverexisted"

    code, message = _error(lambda: sfn.redrive_execution(executionArn=fake_execution_arn))
    assert code == "ExecutionDoesNotExist", f"expected ExecutionDoesNotExist, got {code}"
    expected = f"Execution Does Not Exist: '{fake_execution_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    read_code, read_message = _error(lambda: sfn.describe_execution(executionArn=fake_execution_arn))
    assert read_code == "ExecutionDoesNotExist", (
        f"expected the nonexistent execution to also be absent on read, got {read_code}"
    )
    expected = f"Execution Does Not Exist: '{fake_execution_arn}'"
    assert read_message == expected, f"expected message {expected!r}, got {read_message!r}"


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-activity-")
    arn = sfn.create_activity(
        name=name, tags=[{"key": "sim2real", "value": "true"}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition: str, role_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    last_error = None
    for _ in range(15):
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "true"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except Exception as exc:  # noqa: BLE001 - retry on IAM role propagation delay
            last_error = exc
            time.sleep(2)
    raise AssertionError(f"could not create state machine (role propagation?): {last_error}")


def _poll_activity_task(ctx, activity_arn: str, timeout_s: float = 60.0) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav")
        token = resp.get("taskToken")
        if token:
            return token
    raise AssertionError("never received an activity task in time")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 1.0) -> Any:
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
