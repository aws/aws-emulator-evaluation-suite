"""task-timed-out-error-on-heartbeat-after-window."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "task-timed-out-error-on-heartbeat-after-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskHeartbeat after the HeartbeatSeconds window elapsed fails TaskTimedOut, after an
    in-window heartbeat on the same token succeeded and the execution failed on the timeout."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, activity_arn, heartbeat_seconds=5, timeout_seconds=300)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]

    task_token = _poll_for_task_token(ctx, activity_arn)
    assert task_token, "never received a task token from GetActivityTask"

    # Positive control: the token and SendTaskHeartbeat work while the window is fresh.
    sfn.send_task_heartbeat(taskToken=task_token)

    # That heartbeat restarted the 5s window. Let this one elapse untouched: the execution fails
    # automatically.
    desc = _poll_execution_status(ctx, exec_arn, timeout_s=40.0, interval_s=1.5)
    assert desc["status"] == "FAILED", f"expected FAILED once heartbeat window elapsed, got {desc['status']!r}"

    code, message = _error(lambda: sfn.send_task_heartbeat(taskToken=task_token))
    assert code == "TaskTimedOut", f"expected TaskTimedOut, got {code!r}"
    assert message == f"Task Timed Out: '{activity_arn}'", f"unexpected TaskTimedOut message: {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_sfn_role(ctx, inline_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-behav-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    activity_name = ctx.unique_name("sim2real-behav-activity-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))
    return activity_arn


def _create_state_machine(
    ctx, role_arn: str, activity_arn: str, *, heartbeat_seconds: int | None = None, timeout_seconds: int | None = None
) -> str:
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    task_state: dict[str, Any] = {"Type": "Task", "Resource": activity_arn, "End": True}
    if heartbeat_seconds is not None:
        task_state["HeartbeatSeconds"] = heartbeat_seconds
    if timeout_seconds is not None:
        task_state["TimeoutSeconds"] = timeout_seconds
    definition = json.dumps(
        {
            "Comment": "sim2real activity heartbeat/timeout behavioral check",
            "StartAt": "ActivityStep",
            "States": {"ActivityStep": task_state},
        }
    )
    sm_name = ctx.unique_name("sim2real-behav-sm-")
    # CreateStateMachine rejects a just-created role with AccessDeniedException until its trust
    # policy propagates.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            sm_arn = sfn.create_state_machine(
                name=sm_name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    return sm_arn


def _poll_for_task_token(ctx, activity_arn: str, attempts: int = 3) -> str | None:
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("worker-"))
        token = resp.get("taskToken")
        if token:
            return token
        time.sleep(1.0)
    return None


def _poll_execution_status(ctx, execution_arn: str, *, timeout_s: float = 40.0, interval_s: float = 1.5) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=execution_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        desc = sfn.describe_execution(executionArn=execution_arn)
    return desc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
