"""send-task-failure-null-error-and-cause-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-failure-null-error-and-cause-preserved"
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
    role_name = ctx.unique_name("sim2real-behav-sfnnull-")
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
        name=ctx.unique_name("sim2real-behav-nullact-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, role_arn: str, activity_arn: str) -> str:
    """CreateStateMachine with a single activity Task state, retrying while the fresh role
    propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-nullsm-")
    definition = json.dumps({
        "Comment": "a single activity Task state, re-run once per null combination",
        "StartAt": "DoTask",
        "States": {
            "DoTask": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": 180,
                "End": True,
            }
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


def _poll_activity_task(ctx, activity_arn: str, *, timeout_s: float = 75.0) -> dict:
    """GetActivityTask long-polls up to ~60s server-side; retry on an empty answer."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled within {timeout_s}s: {last!r}")


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 60.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _run_one_failure(ctx, sm_arn: str, activity_arn: str, send_kwargs: dict) -> dict:
    """Start one execution, fail its only task with exactly ``send_kwargs``, return the
    terminal DescribeExecution."""
    sfn = ctx.client("stepfunctions")
    exec_arn = _start_execution(ctx, sm_arn)
    task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=task["taskToken"], **send_kwargs)
    return _wait_terminal(ctx, exec_arn)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskFailure with error and/or cause omitted drives ExecutionFailed to report exactly
    those fields as null, never a substituted empty string or literal 'null'.
    """
    activity_arn = _create_activity(ctx)
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, activity_arn)

    no_cause = _run_one_failure(ctx, sm_arn, activity_arn, {"error": "OnlyError"})
    assert no_cause["status"] == "FAILED", f"expected FAILED, got {no_cause['status']!r}"
    assert no_cause.get("error") == "OnlyError", (
        f"expected error 'OnlyError', got {no_cause.get('error')!r}"
    )
    assert no_cause.get("cause") is None, (
        f"omitted cause came back as {no_cause.get('cause')!r}, expected null"
    )

    no_error = _run_one_failure(ctx, sm_arn, activity_arn, {"cause": "OnlyCause"})
    assert no_error["status"] == "FAILED", f"expected FAILED, got {no_error['status']!r}"
    assert no_error.get("error") is None, (
        f"omitted error came back as {no_error.get('error')!r}, expected null"
    )
    assert no_error.get("cause") == "OnlyCause", (
        f"expected cause 'OnlyCause', got {no_error.get('cause')!r}"
    )

    both_null = _run_one_failure(ctx, sm_arn, activity_arn, {})
    assert both_null["status"] == "FAILED", f"expected FAILED, got {both_null['status']!r}"
    assert both_null.get("error") is None, (
        f"omitted error came back as {both_null.get('error')!r}, expected null"
    )
    assert both_null.get("cause") is None, (
        f"omitted cause came back as {both_null.get('cause')!r}, expected null"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
