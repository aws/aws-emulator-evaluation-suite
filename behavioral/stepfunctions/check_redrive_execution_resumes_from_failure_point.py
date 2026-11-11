"""redrive-execution-resumes-from-failure-point."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-resumes-from-failure-point"
GROUP = 'execution_lifecycle'
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


def _wait_for_status(ctx, exec_arn, statuses, *, timeout_s=60, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} status not in {statuses} within {timeout_s}s: {last!r}")


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


def _full_history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a FAILED execution resumes from the failed Task on the same executionArn,
    scheduling a new activity task, and reaches SUCCEEDED with redriveCount incremented.
    """
    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    activity_arn = act["arn"]
    arn = _create_state_machine(ctx, _asl_activity_task(activity_arn))
    exec_arn = _start_execution(ctx, arn)

    first_task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=first_task["taskToken"], error="BoomOnce", cause="fail the first attempt")
    failed = _wait_execution_complete(ctx, exec_arn)
    assert failed["status"] == "FAILED", f"expected FAILED before redrive, got {failed}"

    sfn.redrive_execution(executionArn=exec_arn)

    _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE"}, timeout_s=30)

    second_task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=second_task["taskToken"], output=json.dumps({"resumed": True}))

    final = _wait_execution_complete(ctx, exec_arn)
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED after the redriven retry succeeds, got {final}"
    assert final.get("redriveCount") == 1, f"expected redriveCount 1 after one RedriveExecution, got {final}"
    assert _get_output(final) == {"resumed": True}, f"expected the resumed run's real output, got {final}"

    history_types = [e["type"] for e in _full_history(ctx, exec_arn)]
    assert "ActivityFailed" in history_types, (
        f"expected the original activity failure preserved in the SAME execution's history, got {history_types}"
    )
    assert "ExecutionRedriven" in history_types, (
        f"expected an ExecutionRedriven event appended to history (not a fresh history), got {history_types}"
    )
    assert history_types.index("ActivityFailed") < history_types.index("ExecutionRedriven"), (
        f"expected the redrive event to be appended AFTER the original failure, got {history_types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
