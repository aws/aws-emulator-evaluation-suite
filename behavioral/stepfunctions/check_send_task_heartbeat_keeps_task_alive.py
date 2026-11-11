"""send-task-heartbeat-keeps-task-alive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-heartbeat-keeps-task-alive"
GROUP = 'activities'
SERVICES = ['stepfunctions']


_SFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx):
    """An execution role this check creates, trusted by states.amazonaws.com."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_SFN_TRUST),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _asl_activity_task(activity_arn, timeout_seconds=300, heartbeat_seconds=None):
    state = {
        "Type": "Task",
        "Resource": activity_arn,
        "TimeoutSeconds": timeout_seconds,
        "End": True,
    }
    if heartbeat_seconds is not None:
        state["HeartbeatSeconds"] = heartbeat_seconds
    return {"Comment": "behavioral-activity", "StartAt": "T", "States": {"T": state}}


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": "1"}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled for {activity_arn} within {timeout_s}s")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskHeartbeat calls sent inside HeartbeatSeconds keep an activity task's execution RUNNING past
    one heartbeat window, and it SUCCEEDS with output {"kept_alive": true} only after SendTaskSuccess."""
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    activity_arn = act["arn"]
    heartbeat_seconds = 15
    # A third of the window between heartbeats leaves room for poll overshoot and round trips.
    gap_seconds = heartbeat_seconds // 3
    arn = _create_state_machine(
        ctx, _asl_activity_task(activity_arn, timeout_seconds=300, heartbeat_seconds=heartbeat_seconds)
    )
    exec_arn = _start_execution(ctx, arn)

    task = _poll_activity_task(ctx, activity_arn)
    task_token = task["taskToken"]

    def wait_confirming_still_running(seconds):
        """Actively poll DescribeExecution for `seconds`, asserting RUNNING on
        every poll — a real-time wait that also continuously verifies the
        execution hasn't ended early (unlike a blind sleep)."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            r = sfn.describe_execution(executionArn=exec_arn)
            if r["status"] != "RUNNING":
                raise AssertionError(f"execution ended before the heartbeat window elapsed: {r}")
            time.sleep(1.0)

    # Heartbeat 4 times, each spaced well under the heartbeat window, spanning a
    # TOTAL elapsed time greater than heartbeat_seconds itself — proving the
    # window kept getting reset rather than accumulating toward a timeout.
    total_elapsed = 0.0
    for _ in range(4):
        wait_confirming_still_running(gap_seconds)
        total_elapsed += gap_seconds
        sfn.send_task_heartbeat(taskToken=task_token)
        mid = sfn.describe_execution(executionArn=exec_arn)
        assert mid["status"] == "RUNNING", f"execution must stay RUNNING while heartbeats continue, got {mid}"

    assert total_elapsed > heartbeat_seconds, "test didn't actually span more than one heartbeat window"

    sfn.send_task_success(taskToken=task_token, output=json.dumps({"kept_alive": True}))
    final = _wait_execution_complete(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED — heartbeats should have prevented any timeout, got {final}"
    )
    assert _get_output(final) == {"kept_alive": True}, (
        f"expected the SendTaskSuccess output to be relayed verbatim, got {_get_output(final)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
