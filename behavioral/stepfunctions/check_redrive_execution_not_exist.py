"""redrive-execution-not-exist."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-not-exist"
GROUP = 'errors'
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


def _asl_activity_task(activity_arn, timeout_seconds=300):
    return {
        "Comment": "behavioral-activity",
        "StartAt": "T",
        "States": {
            "T": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": timeout_seconds, "End": True}
        },
    }


def _create_state_machine(ctx, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name, definition=json.dumps(definition), roleArn=_create_sfn_role(ctx), type="STANDARD"
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _start_execution(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
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


def _wait_for_status(ctx, exec_arn, statuses, *, timeout_s=30, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} status not in {statuses} within {timeout_s}s: {last!r}")


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled for {activity_arn} within {timeout_s}s")


def _execution_arn(ctx, state_machine_name, execution_name):
    return f"arn:aws:states:{ctx.region}:{ctx.account}:execution:{state_machine_name}:{execution_name}"


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("RedriveExecution against a nonexistent execution unexpectedly succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a well-formed but unknown execution ARN fails with ExecutionDoesNotExist and
    the exact message, while a real FAILED execution redrives in place and then SUCCEEDS."""
    sfn = ctx.client("stepfunctions")
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, _asl_activity_task(activity_arn))
    exec_arn = _start_execution(ctx, sm_arn)

    first_task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=first_task["taskToken"], error="BoomOnce", cause="deliberate")
    failed = _wait_execution_complete(ctx, exec_arn)
    assert failed["status"] == "FAILED", f"expected FAILED before redrive, got {failed}"

    sfn.redrive_execution(executionArn=exec_arn)
    redriven = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE"})
    assert redriven["executionArn"] == exec_arn, "positive-control redrive must resume the SAME execution"

    second_task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=second_task["taskToken"], output="{}")
    final = _wait_execution_complete(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", f"positive control: expected SUCCEEDED after real redrive, got {final}"

    fake_arn = _execution_arn(ctx, ctx.unique_name("sm-"), ctx.unique_name("exec-"))
    code, message = _error(lambda: sfn.redrive_execution(executionArn=fake_arn))
    assert code == "ExecutionDoesNotExist", f"expected ExecutionDoesNotExist, got {code}"
    expected = f"Execution Does Not Exist: '{fake_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
