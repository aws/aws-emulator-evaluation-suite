"""reject-delete-nonempty-activity-in-use."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "reject-delete-nonempty-activity-in-use"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


# timing:real-time — workflow: 15 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """DeleteActivity with an outstanding task token is accepted: the activity reads as gone,
    the held token is refused with TaskDoesNotExist, and the execution fails with States.Timeout
    once its own TimeoutSeconds elapses.
    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html"""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    activity_name = ctx.unique_name("sim2real-activity-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": "1"}]
    )["activityArn"]
    state = {"activity_deleted": False}

    def _cleanup_activity() -> None:
        if not state["activity_deleted"]:
            sfn.delete_activity(activityArn=activity_arn)

    ctx.on_cleanup(_cleanup_activity)

    sm_name = ctx.unique_name("sim2real-sfn-actwait-")
    definition = json.dumps(
        {
            "StartAt": "WaitForWorker",
            "States": {
                "WaitForWorker": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": 15,
                    "End": True,
                }
            },
        }
    )
    create_resp = _create_state_machine_with_retry(
        ctx, sm_name, definition, role_arn, tags=[{"key": "sim2real", "value": "1"}]
    )
    sm_arn = create_resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_resp = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"k": "v"})
    )
    exec_arn = exec_resp["executionArn"]
    ctx.on_cleanup(lambda: _stop_execution_quietly(sfn, exec_arn))

    task = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-worker")
    task_token = task.get("taskToken")
    assert task_token, "worker never received a task token for the running execution"

    # AWS accepts the delete while a worker holds the task token.
    sfn.delete_activity(activityArn=activity_arn)
    state["activity_deleted"] = True

    # A delete that returns 200 without removing anything must not read as gone.
    try:
        sfn.describe_activity(activityArn=activity_arn)
        raise AssertionError("activity still describable after delete_activity succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "ActivityDoesNotExist", f"expected ActivityDoesNotExist for a deleted activity, got {code}"
        expected = f"Activity Does Not Exist: '{activity_arn}'"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    try:
        sfn.send_task_success(taskToken=task_token, output=json.dumps({"ok": True}))
        raise AssertionError("SendTaskSuccess on a deleted activity's token unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "TaskDoesNotExist", f"unexpected error completing task after activity deletion: {code}"
        expected = f"Activity Does Not Exist: '{activity_arn}'"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    final = _wait_execution_terminal(ctx, exec_arn, timeout_s=45)
    assert final["status"] == "FAILED", (
        f"expected the execution to fail cleanly after activity deletion, got {final['status']}"
    )
    assert final.get("error") == "States.Timeout", (
        f"expected the Task state's own TimeoutSeconds to close the execution with States.Timeout, "
        f"got {final.get('error')!r} / {final.get('cause')!r}"
    )


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _stop_execution_quietly(sfn: Any, execution_arn: str) -> None:
    """The execution is already terminal by the time cleanup runs; StopExecution on it is a
    no-op on real AWS, but a genuine failure to stop a still-running one must not be swallowed."""
    from botocore.exceptions import ClientError

    try:
        sfn.stop_execution(executionArn=execution_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ExecutionDoesNotExist":
            return
        raise


def _wait_execution_terminal(
    ctx: Any, execution_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0
) -> dict:
    sfn = ctx.client("stepfunctions")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    resp = {"status": "RUNNING"}
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(interval_s)
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
