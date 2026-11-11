"""activity-heartbeat-timeout-catcher-order-decides-winner."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-heartbeat-timeout-catcher-order-decides-winner"
GROUP = "activities"
SERVICES = ["stepfunctions"]

_HEARTBEAT_SECONDS = 5
_TASK_TIMEOUT_SECONDS = 120
_HEARTBEAT_TIMEOUT_ERROR = "States.HeartbeatTimeout"
_TIMEOUT_ERROR = "States.Timeout"


def _definition(first_error, second_error):
    """A single activity Task whose Catch list carries both error names, first vs second."""
    return {
        "Comment": "one activity task with both a heartbeat clock and a task clock, caught twice",
        "StartAt": "HandOff",
        "States": {
            "HandOff": {
                "Type": "Task",
                "Resource": "{activity_arn}",
                "HeartbeatSeconds": _HEARTBEAT_SECONDS,
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                "Catch": [
                    {"ErrorEquals": [first_error], "Next": _label(first_error)},
                    {"ErrorEquals": [second_error], "Next": _label(second_error)},
                ],
                "End": True,
            },
            _label(_HEARTBEAT_TIMEOUT_ERROR): {
                "Type": "Pass",
                "Result": "heartbeat-timeout-catcher-won",
                "End": True,
            },
            _label(_TIMEOUT_ERROR): {
                "Type": "Pass",
                "Result": "timeout-catcher-won",
                "End": True,
            },
        },
    }


def _label(error_name):
    return "CaughtBy" + error_name.replace(".", "")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A heartbeat timeout matches both States.HeartbeatTimeout and States.Timeout catchers;
    which one wins is decided by catcher order, never by error specificity.
    """
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)

    def_heartbeat_first = json.loads(
        json.dumps(_definition(_HEARTBEAT_TIMEOUT_ERROR, _TIMEOUT_ERROR)).replace(
            "{activity_arn}", activity_arn
        )
    )
    def_timeout_first = json.loads(
        json.dumps(_definition(_TIMEOUT_ERROR, _HEARTBEAT_TIMEOUT_ERROR)).replace(
            "{activity_arn}", activity_arn
        )
    )

    sm_heartbeat_first = _create_state_machine(ctx, def_heartbeat_first, role_arn)
    sm_timeout_first = _create_state_machine(ctx, def_timeout_first, role_arn)

    won_heartbeat_first = _abandon_and_get_output(ctx, activity_arn, sm_heartbeat_first)
    assert won_heartbeat_first == "heartbeat-timeout-catcher-won", (
        f"with States.HeartbeatTimeout listed first in Catch, the execution output was "
        f"{won_heartbeat_first!r}, expected the first-listed catcher to win"
    )

    won_timeout_first = _abandon_and_get_output(ctx, activity_arn, sm_timeout_first)
    assert won_timeout_first == "timeout-catcher-won", (
        f"with States.Timeout listed first in Catch, the execution output was "
        f"{won_timeout_first!r}, expected the first-listed catcher to win"
    )


def _abandon_and_get_output(ctx, activity_arn, sm_arn):
    """Start an execution, claim its activity task, then abandon it: the heartbeat clock lapses
    with neither SendTaskHeartbeat nor SendTaskSuccess/Failure ever called."""
    exec_arn = _start_execution(ctx, sm_arn, {})
    claimed = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    assert claimed.get("taskToken"), f"the worker was handed no task token: {claimed!r}"
    final = _wait_terminal(ctx, exec_arn, timeout_s=_HEARTBEAT_SECONDS + 90)
    assert final["status"] == "SUCCEEDED", (
        f"a matched Catch must let the execution finish successfully, got "
        f"status={final['status']!r}: {final.get('error')!r} / {final.get('cause')!r}"
    )
    return json.loads(final["output"])


# ===== helpers =====
def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role with no permissions attached: an Activity
    task needs none, because the worker calls SendTaskSuccess with its own credentials."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
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
        Description="sim2real-behav sfn activity execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"),
        tags=[{"key": "sim2real", "value": "1"}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD"):
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates (IAM
    exposes no condition to poll for that)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _start_execution(ctx, sm_arn, input_payload):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll_activity_task(ctx, activity_arn, *, worker_name, timeout_s=120.0):
    """GetActivityTask long-polls ~60 s server-side and returns empty on expiry; re-call it."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn, workerName=worker_name)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(
        f"no activity task was ever handed to a worker within {timeout_s}s; last poll {last!r}"
    )


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
