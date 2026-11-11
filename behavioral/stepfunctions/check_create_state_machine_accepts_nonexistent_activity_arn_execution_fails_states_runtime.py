"""create-state-machine-accepts-nonexistent-activity-arn-execution-fails-states-runtime."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-accepts-nonexistent-activity-arn-execution-fails-states-runtime"
GROUP = "activities"
SERVICES = ["stepfunctions"]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateStateMachine does not validate that a Task's Activity ARN exists: it is accepted,
    and only StartExecution fails States.Runtime, naming the missing activity and the state."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    missing_activity_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:activity:"
        f"{ctx.unique_name('sim2real-behav-noact-')}"
    )
    state_name = "DoWork"
    definition = {
        "Comment": "a Task naming an Activity that was never created",
        "StartAt": state_name,
        "States": {state_name: {"Type": "Task", "Resource": missing_activity_arn, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, role_arn, definition)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))

    desc = _poll_terminal(ctx, exec_arn, timeout_s=40.0)
    assert desc["status"] == "FAILED", (
        f"expected the execution to FAIL against the nonexistent activity, got "
        f"{desc['status']!r}: {desc.get('cause')!r}"
    )
    assert desc.get("error") == "States.Runtime", (
        f"expected error States.Runtime, got {desc.get('error')!r}: {desc.get('cause')!r}"
    )
    cause = desc.get("cause") or ""
    expected_tail = f"The activity {missing_activity_arn} does not exist."
    assert cause.endswith(expected_tail), (
        f"expected the cause to end with {expected_tail!r}, got {cause!r}"
    )
    assert state_name in cause, (
        f"expected the cause to name the failing state {state_name!r}, got {cause!r}"
    )

    types = [e["type"] for e in sfn.get_execution_history(executionArn=exec_arn)["events"]]
    assert "ActivityScheduled" not in types, (
        f"the nonexistent activity was scheduled a task despite not existing: {types!r}"
    )
    assert types[-1] == "ExecutionFailed", (
        f"the failed execution's history does not end ExecutionFailed: {types!r}"
    )

    # Positive control: the same Resource shape, naming an activity that really exists, runs to
    # a worker instead of failing at runtime.
    control_activity_arn = _create_activity(ctx)
    control_definition = {
        "Comment": "the same shape, naming a real activity",
        "StartAt": state_name,
        "States": {state_name: {"Type": "Task", "Resource": control_activity_arn, "End": True}},
    }
    control_sm_arn = _create_state_machine(ctx, role_arn, control_definition)
    control_exec_arn = sfn.start_execution(stateMachineArn=control_sm_arn, input="{}")[
        "executionArn"
    ]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, control_exec_arn))

    control_task = _poll_for_task_token(ctx, control_activity_arn)
    assert control_task, "the positive control's real activity never received a task"
    sfn.send_task_success(taskToken=control_task, output=json.dumps({"ok": True}))
    control_desc = _poll_terminal(ctx, control_exec_arn, timeout_s=30.0)
    assert control_desc["status"] == "SUCCEEDED", (
        f"the positive control ended {control_desc['status']!r}, expected SUCCEEDED: "
        f"{control_desc.get('error')!r} {control_desc.get('cause')!r}"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"), tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
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


def _poll_terminal(ctx, exec_arn, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = sfn.describe_execution(executionArn=exec_arn)
    while last["status"] not in _TERMINAL and time.monotonic() < deadline:
        time.sleep(2.0)
        last = sfn.describe_execution(executionArn=exec_arn)
    if last["status"] not in _TERMINAL:
        raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")
    return last


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
