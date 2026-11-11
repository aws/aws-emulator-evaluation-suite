"""send-task-heartbeat-after-timeout-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-heartbeat-after-timeout-fails"
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
    tags = [{"key": "sim2real", "value": "1"}]
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=tags,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    tags = [{"key": "sim2real", "value": "1"}]
    arn = sfn.create_activity(name=name, tags=tags)["activityArn"]
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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled for {activity_arn} within {timeout_s}s")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task that never heartbeats within its short HeartbeatSeconds ends the execution FAILED or
    TIMED_OUT, and a later SendTaskHeartbeat on its token fails with TaskTimedOut and the exact message."""
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    activity_arn = act["arn"]
    arn = _create_state_machine(ctx, _asl_activity_task(activity_arn, timeout_seconds=120, heartbeat_seconds=5))
    exec_arn = _start_execution(ctx, arn)

    task = _poll_activity_task(ctx, activity_arn)
    task_token = task["taskToken"]

    # Positive control: heartbeating this SAME token while it is still live must
    # succeed, so a target that rejects every SendTaskHeartbeat call cannot be
    # mistaken for one that correctly rejects only an expired token.
    sfn.send_task_heartbeat(taskToken=task_token)

    # Now deliberately send NO further heartbeat — let the HeartbeatSeconds=5 window lapse.

    result = _wait_execution_complete(ctx, exec_arn, timeout_s=60)
    assert result["status"] in ("FAILED", "TIMED_OUT"), f"expected FAILED/TIMED_OUT on heartbeat timeout, got {result}"

    code, message = _error(lambda: sfn.send_task_heartbeat(taskToken=task_token))
    assert code == "TaskTimedOut", f"expected TaskTimedOut on a heartbeat sent after the window lapsed, got {code}"
    expected = f"Task Timed Out: '{activity_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
