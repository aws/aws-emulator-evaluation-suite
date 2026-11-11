"""send-task-failure-invalid-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-failure-invalid-token"
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


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK}])["activityArn"]
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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskFailure on a token already closed by SendTaskSuccess fails with TaskTimedOut and the exact
    message, and the execution stays SUCCEEDED with the first completion's output {"first": true}."""
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    definition = {
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": act["arn"], "TimeoutSeconds": 300, "End": True}},
    }
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn)
    task = _poll_activity_task(ctx, act["arn"])

    sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"first": True}))
    final = _wait_execution_complete(ctx, exec_arn, timeout_s=60)
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED from the first completion, got {final}"

    code, message = _error(
        lambda: sfn.send_task_failure(taskToken=task["taskToken"], error="TooLate", cause="already completed")
    )
    assert code == "TaskTimedOut", f"expected TaskTimedOut for SendTaskFailure on an already-completed token, got {code}"
    expected = f"Task Timed Out: '{act['arn']}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = sfn.describe_execution(executionArn=exec_arn)
    assert after["status"] == "SUCCEEDED", (
        f"rejected SendTaskFailure must not disturb the prior SUCCEEDED outcome, got {after['status']!r}"
    )
    assert json.loads(after["output"]) == {"first": True}, (
        f"rejected SendTaskFailure must not disturb the prior output, got {after['output']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
