"""send-task-heartbeat-task-does-not-exist."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-heartbeat-task-does-not-exist"
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


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


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskHeartbeat against a syntactically-valid token whose underlying
    ACTIVITY has since been deleted must fail TaskDoesNotExist — never
    silently accept a heartbeat for a task whose activity resource is gone.
    """
    sfn = ctx.client("stepfunctions")
    activity_arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    arn = _create_state_machine(ctx, _asl_activity_task(activity_arn, timeout_seconds=60))
    exec_arn = _start_execution(ctx, arn)

    task = _poll_activity_task(ctx, activity_arn)
    task_token = task["taskToken"]

    # Positive control: the same token, against the still-live activity, must
    # heartbeat cleanly. Without this, a target that rejects every heartbeat
    # call (not just ones for a deleted activity) would pass this check too.
    sfn.send_task_heartbeat(taskToken=task_token)

    sfn.delete_activity(activityArn=activity_arn)

    # Independent read confirming the activity is actually gone, not just
    # assumed gone because the delete call didn't raise.
    describe_code, describe_message = _error(lambda: sfn.describe_activity(activityArn=activity_arn))
    assert describe_code == "ActivityDoesNotExist", (
        f"expected ActivityDoesNotExist from DescribeActivity after delete, got {describe_code}"
    )
    expected = f"Activity Does Not Exist: '{activity_arn}'"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    code, message = _error(lambda: sfn.send_task_heartbeat(taskToken=task_token))
    assert code == "TaskDoesNotExist", f"expected TaskDoesNotExist after deleting the underlying activity, got {code}"
    expected = f"Activity Does Not Exist: '{activity_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Best-effort: end the now-orphaned execution rather than leave it dangling
    # for the full TimeoutSeconds window.
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
