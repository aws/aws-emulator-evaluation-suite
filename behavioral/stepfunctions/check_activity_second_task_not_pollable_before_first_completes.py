"""activity-second-task-not-pollable-before-first-completes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-second-task-not-pollable-before-first-completes"
GROUP = 'activities'
SERVICES = ['stepfunctions']

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnseq-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-seqact-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, role_arn: str, activity_arn: str) -> str:
    """CreateStateMachine with two sequential Task states sharing one activity, retrying while
    the fresh role propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-seqsm-")
    definition = json.dumps({
        "Comment": "two sequential Task states on the same activity",
        "StartAt": "First",
        "States": {
            "First": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": 180,
                "Next": "Second",
            },
            "Second": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": 180,
                "End": True,
            },
        },
    })
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last_err!r}")


def _start_execution(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"), input="{}",
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _get_activity_task(ctx, activity_arn: str) -> dict:
    """One GetActivityTask call: AWS long-polls this up to ~60s server-side before answering
    empty, so a single call that returns no token already proves nothing was queued for that
    whole window."""
    return ctx.client("stepfunctions").get_activity_task(activityArn=activity_arn)


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 120.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The second of two sequential activity Task states is not scheduled, and so never answers
    GetActivityTask, until SendTaskSuccess completes the first.
    """
    activity_arn = _create_activity(ctx)
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, activity_arn)
    exec_arn = _start_execution(ctx, sm_arn)

    first = _get_activity_task(ctx, activity_arn)
    assert first.get("taskToken"), f"the first task never reached the activity: {first!r}"

    # Before completing First, poll once more. GetActivityTask long-polls up to ~60s
    # server-side, so an empty answer here is itself the proof the second task was not queued
    # during that whole window — not a race that happened to miss it.
    premature = _get_activity_task(ctx, activity_arn)
    assert not premature.get("taskToken"), (
        f"GetActivityTask handed out a second task {premature!r} before the first task "
        f"({first['taskToken'][:12]}...) was completed"
    )

    ctx.client("stepfunctions").send_task_success(
        taskToken=first["taskToken"], output=json.dumps({"stage": "first-done"})
    )

    second = _get_activity_task(ctx, activity_arn)
    assert second.get("taskToken"), (
        f"the second task was never scheduled after the first completed: {second!r}"
    )
    assert second["taskToken"] != first["taskToken"], (
        "the second task was handed out under the first task's own token"
    )
    ctx.client("stepfunctions").send_task_success(
        taskToken=second["taskToken"], output=json.dumps({"stage": "second-done"})
    )

    final = _wait_terminal(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", (
        f"the execution ended {final['status']!r} after both tasks replied: "
        f"{final.get('error')!r} / {final.get('cause')!r}"
    )
    assert json.loads(final["output"]) == {"stage": "second-done"}, (
        f"final output was {final['output']!r}, expected the second task's reply"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
