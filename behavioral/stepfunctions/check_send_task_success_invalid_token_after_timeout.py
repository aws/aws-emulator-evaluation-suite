"""send-task-success-invalid-token-after-timeout."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-success-invalid-token-after-timeout"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    The state machines here call no AWS API on the customer's behalf, so the role carries no
    permissions. It is created rather than looked up because a role the check did not create
    is account configuration, not a service contract.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine on a fresh role, retrying the one error IAM propagation can produce.

    A freshly created role is not instantly assumable and IAM exposes no condition to poll
    for that, so the bounded AccessDeniedException retry is the wait.
    """
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
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


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    # GetActivityTask long-polls up to ~60s server-side; use a fresh client and retry until a token appears.
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected SUCCESS raises AssertionError, so a
    target accepting a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskSuccess on a token whose task closed by heartbeat timeout fails with TaskTimedOut and the
    exact message and leaves the FAILED or TIMED_OUT execution unchanged, while SendTaskSuccess on a
    live token completes its execution."""
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    definition = {
        "StartAt": "T",
        "States": {
            "T": {
                "Type": "Task",
                "Resource": act["arn"],
                "TimeoutSeconds": 120,
                "HeartbeatSeconds": 5,
                "End": True,
            }
        },
    }
    arn = _create_state_machine(ctx, definition)

    control_exec = _start_execution(ctx, arn)
    control_task = _poll_activity_task(ctx, act["arn"])
    sfn.send_task_success(taskToken=control_task["taskToken"], output=json.dumps({"ok": True}))
    control_result = _wait_execution_complete(ctx, control_exec, timeout_s=30)
    assert control_result["status"] == "SUCCEEDED", (
        f"positive control: expected SUCCEEDED for SendTaskSuccess on a live token, got {control_result}"
    )

    exec_arn = _start_execution(ctx, arn)
    task = _poll_activity_task(ctx, act["arn"])
    # No heartbeat — let the HeartbeatSeconds=5 window lapse and close the task.

    result = _wait_execution_complete(ctx, exec_arn, timeout_s=60)
    assert result["status"] in ("FAILED", "TIMED_OUT"), f"expected FAILED/TIMED_OUT on heartbeat timeout, got {result}"

    error = _client_error(lambda: sfn.send_task_success(taskToken=task["taskToken"], output="{}"))
    assert error.get("Code") == "TaskTimedOut", (
        f"expected TaskTimedOut for SendTaskSuccess on an already-closed token, got {error!r}"
    )
    expected_message = f"Task Timed Out: '{act['arn']}'"
    assert error.get("Message") == expected_message, (
        f"expected TaskTimedOut message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Independent read: the rejected SendTaskSuccess must not have taken effect —
    # the execution stays exactly as terminal-failed as it already was, never SUCCEEDED.
    after = sfn.describe_execution(executionArn=exec_arn)
    assert after["status"] == result["status"], (
        f"expected execution status unchanged by the rejected SendTaskSuccess, "
        f"was {result['status']!r} now {after['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
