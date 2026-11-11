"""activity-heartbeatsecondspath-timeout-fails-execution."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-heartbeatsecondspath-timeout-fails-execution"
GROUP = "visibility-timeout-ttl"
SERVICES = ["stepfunctions"]

_HEARTBEAT_SECONDS = 5
_TIMEOUT_SECONDS = 300


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An activity task with HeartbeatSecondsPath and TimeoutSecondsPath, both resolved from the
    execution input, whose worker never heartbeats fails States.Timeout from the short heartbeat
    window, well before the much longer TimeoutSecondsPath value would end it."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, activity_arn)

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        input=json.dumps({"hb": _HEARTBEAT_SECONDS, "timeout": _TIMEOUT_SECONDS}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))

    task_token = _poll_for_task_token(ctx, activity_arn)
    assert task_token, "never received a task token from GetActivityTask"

    # Deliberately send no heartbeat: the 5s HeartbeatSecondsPath window must expire and fail
    # the execution long before the 300s TimeoutSecondsPath would.
    desc = _poll_execution_status(ctx, exec_arn, timeout_s=40.0)
    assert desc["status"] == "FAILED", (
        f"expected FAILED once the HeartbeatSecondsPath window elapsed, got {desc['status']!r}"
    )
    assert desc.get("error") == "States.Timeout", (
        f"expected error States.Timeout, got {desc.get('error')!r}: {desc.get('cause')!r}"
    )

    events = sfn.get_execution_history(executionArn=exec_arn)["events"]
    types = [e["type"] for e in events]
    assert "ActivityTimedOut" in types, (
        f"expected ActivityTimedOut in execution history, got {types}"
    )

    code, message = _error(lambda: sfn.send_task_heartbeat(taskToken=task_token))
    assert code == "TaskTimedOut", f"expected TaskTimedOut, got {code!r}"
    assert message == f"Task Timed Out: '{activity_arn}'", (
        f"unexpected TaskTimedOut message: {message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    activity_name = ctx.unique_name("sim2real-behav-activity-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))
    return activity_arn


def _create_state_machine(ctx, role_arn: str, activity_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created role's
    trust policy propagates."""
    sfn = ctx.client("stepfunctions")
    task_state: dict[str, Any] = {
        "Type": "Task",
        "Resource": activity_arn,
        "HeartbeatSecondsPath": "$.hb",
        "TimeoutSecondsPath": "$.timeout",
        "End": True,
    }
    definition = json.dumps(
        {
            "Comment": "sim2real activity HeartbeatSecondsPath+TimeoutSecondsPath behavioral check",
            "StartAt": "ActivityStep",
            "States": {"ActivityStep": task_state},
        }
    )
    sm_name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            sm_arn = sfn.create_state_machine(
                name=sm_name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
            return sm_arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last_err!r}")


def _poll_for_task_token(ctx, activity_arn: str, *, timeout_s: float = 60.0) -> str | None:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(
            activityArn=activity_arn, workerName=ctx.unique_name("worker-")
        )
        token = resp.get("taskToken")
        if token:
            return token
        time.sleep(2.0)
    return None


def _poll_execution_status(ctx, execution_arn: str, *, timeout_s: float = 40.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=execution_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(2.0)
        desc = sfn.describe_execution(executionArn=execution_arn)
    return desc


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
