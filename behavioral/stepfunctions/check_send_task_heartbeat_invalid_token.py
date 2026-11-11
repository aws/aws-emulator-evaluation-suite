"""send-task-heartbeat-invalid-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-heartbeat-invalid-token"
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


def _create_state_machine(ctx, definition, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type="STANDARD",
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled for {activity_arn} within {timeout_s}s")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskHeartbeat with a malformed task token fails with InvalidToken and the exact message, while
    a real activity task's heartbeat succeeds and its execution stays RUNNING after the bogus call."""
    sfn = ctx.client("stepfunctions")
    activity_arn = sfn.create_activity(name=ctx.unique_name("sim2real-behav-act-"))["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))
    definition = {
        "StartAt": "T",
        "States": {"T": {
            "Type": "Task",
            "Resource": activity_arn,
            "TimeoutSeconds": 300,
            "HeartbeatSeconds": 60,
            "End": True,
        }},
    }
    sm_arn = _create_state_machine(ctx, definition)
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))

    task = _poll_activity_task(ctx, activity_arn)
    real_token = task["taskToken"]

    # Positive control: a real task token's heartbeat must succeed on this wiring.
    sfn.send_task_heartbeat(taskToken=real_token)
    control = sfn.describe_execution(executionArn=exec_arn)
    assert control["status"] == "RUNNING", (
        f"execution should still be RUNNING after a valid heartbeat, got {control['status']}"
    )

    error = _client_error(lambda: sfn.send_task_heartbeat(taskToken="not-a-real-task-token"))
    code = error.get("Code")
    assert code == "InvalidToken", f"expected InvalidToken, got {code}"
    expected = "Invalid Token: 'Invalid token'"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    after = sfn.describe_execution(executionArn=exec_arn)
    assert after["status"] == "RUNNING", (
        f"malformed heartbeat call must not affect the real execution, got {after['status']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
