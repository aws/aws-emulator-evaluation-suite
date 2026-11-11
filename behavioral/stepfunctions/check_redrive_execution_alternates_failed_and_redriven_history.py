"""redrive-execution-alternates-failed-and-redriven-history."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-alternates-failed-and-redriven-history"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]


def _create_sfn_role(ctx):
    """An execution role this check creates, trusted by states.amazonaws.com."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"), tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _start_execution(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-")
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    """GetActivityTask long-polls up to ~60s server-side; retry the call if it comes back empty."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"no activity task scheduled for {activity_arn} within {timeout_s}s")


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
    """Repeated RedriveExecution on a FAILED execution leaves history alternating
    ExecutionFailed/ExecutionRedriven, each ExecutionRedriven's timestamp equals its
    redriveDate, and its event details carry the resulting redriveCount.
    """
    sfn = ctx.client("stepfunctions")
    activity_arn = _create_activity(ctx)
    role_arn = _create_sfn_role(ctx)
    definition = {
        "Comment": "one activity task, failed and redriven twice before it succeeds",
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": 300, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn = _start_execution(ctx, sm_arn)

    task_1 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=task_1["taskToken"], error="E1", cause="C1")
    failed_1 = _wait_for_status(ctx, exec_arn, {"FAILED"})
    assert failed_1["status"] == "FAILED", f"expected FAILED after the first SendTaskFailure, got {failed_1!r}"

    redrive_1 = sfn.redrive_execution(executionArn=exec_arn)
    running_1 = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE"})
    assert running_1["redriveCount"] == 1, f"expected redriveCount 1, got {running_1!r}"

    task_2 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=task_2["taskToken"], error="E2", cause="C2")
    failed_2 = _wait_for_status(ctx, exec_arn, {"FAILED"})
    assert failed_2["redriveCount"] == 1, (
        f"re-failing a redriven execution must not by itself change redriveCount, got {failed_2!r}"
    )

    redrive_2 = sfn.redrive_execution(executionArn=exec_arn)
    running_2 = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE"})
    assert running_2["redriveCount"] == 2, f"expected redriveCount 2, got {running_2!r}"

    task_3 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=task_3["taskToken"], output=json.dumps({"resumed": True}))
    final = _wait_for_status(ctx, exec_arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"})
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED after the second redrive's retry, got {final!r}"
    assert final["redriveCount"] == 2, f"expected final redriveCount 2, got {final!r}"

    history = _full_history(ctx, exec_arn)
    types = [e["type"] for e in history]
    core = [t for t in types if t in ("ExecutionFailed", "ExecutionRedriven")]
    assert core == ["ExecutionFailed", "ExecutionRedriven", "ExecutionFailed", "ExecutionRedriven"], (
        f"expected ExecutionFailed/ExecutionRedriven to strictly alternate, got {core!r}"
    )

    redriven_events = [e for e in history if e["type"] == "ExecutionRedriven"]
    assert len(redriven_events) == 2, f"expected two ExecutionRedriven events, got {types!r}"
    for i, (event, redrive_resp) in enumerate(zip(redriven_events, (redrive_1, redrive_2)), start=1):
        assert event["timestamp"] == redrive_resp["redriveDate"], (
            f"ExecutionRedriven #{i} timestamp {event['timestamp']!r} does not match its "
            f"RedriveExecution response's redriveDate {redrive_resp['redriveDate']!r}"
        )
        assert event["executionRedrivenEventDetails"]["redriveCount"] == i, (
            f"ExecutionRedriven #{i} details carry redriveCount "
            f"{event['executionRedrivenEventDetails']['redriveCount']!r}, expected {i!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
