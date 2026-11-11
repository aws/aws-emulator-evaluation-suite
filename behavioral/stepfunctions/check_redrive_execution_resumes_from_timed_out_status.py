"""redrive-execution-resumes-from-timed-out-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-resumes-from-timed-out-status"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]

#: Short, so the execution-level deadline elapses quickly and twice within budget.
_TIMEOUT_SECONDS = 8


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


def _wait_for_event_count(ctx, exec_arn, event_type, count, *, timeout_s=30):
    """Poll GetExecutionHistory until ``event_type`` appears ``count`` times."""
    deadline = time.monotonic() + timeout_s
    history = []
    while time.monotonic() < deadline:
        history = _full_history(ctx, exec_arn)
        if sum(1 for e in history if e["type"] == event_type) >= count:
            return history
        time.sleep(1.0)
    types = [e["type"] for e in history]
    raise AssertionError(f"{event_type} did not reach count {count} within {timeout_s}s: {types!r}")


# timing:real-time — workflow: 8 s https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """RedriveExecution on a TIMED_OUT execution reschedules a fresh activity task; redriving
    an unclaimed task twice re-times-out the execution each time and redriveCount reaches 2.
    """
    sfn = ctx.client("stepfunctions")
    activity_arn = _create_activity(ctx)
    role_arn = _create_sfn_role(ctx)
    definition = {
        "Comment": "the whole execution times out while one activity task sits unclaimed",
        "TimeoutSeconds": _TIMEOUT_SECONDS,
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": 300, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn = _start_execution(ctx, sm_arn)

    timed_out_1 = _wait_for_status(
        ctx, exec_arn, {"TIMED_OUT"}, timeout_s=_TIMEOUT_SECONDS + 60
    )
    assert timed_out_1["status"] == "TIMED_OUT", (
        f"expected TIMED_OUT once the execution-level TimeoutSeconds elapsed, got {timed_out_1!r}"
    )
    assert "output" not in timed_out_1, f"a timed-out execution carries an output: {timed_out_1!r}"

    history_1 = [e["type"] for e in _full_history(ctx, exec_arn)]
    assert history_1.index("ActivityScheduled") < history_1.index("ExecutionTimedOut"), (
        f"expected ActivityScheduled before ExecutionTimedOut, got {history_1!r}"
    )

    redrive_1 = sfn.redrive_execution(executionArn=exec_arn)
    after_redrive_1 = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE", "TIMED_OUT"})
    assert after_redrive_1["redriveCount"] == 1, (
        f"expected redriveCount 1 after the first RedriveExecution, got {after_redrive_1!r}"
    )

    history_2 = _wait_for_event_count(ctx, exec_arn, "ActivityScheduled", 2)
    types_2 = [e["type"] for e in history_2]
    assert types_2.count("ExecutionRedriven") == 1, f"expected one ExecutionRedriven, got {types_2!r}"
    redriven_event = [e for e in history_2 if e["type"] == "ExecutionRedriven"][0]
    assert redriven_event["timestamp"] == redrive_1["redriveDate"], (
        f"ExecutionRedriven timestamp {redriven_event['timestamp']!r} does not match the "
        f"RedriveExecution response's redriveDate {redrive_1['redriveDate']!r}"
    )

    timed_out_2 = _wait_for_status(
        ctx, exec_arn, {"TIMED_OUT"}, timeout_s=_TIMEOUT_SECONDS + 60
    )
    assert timed_out_2["status"] == "TIMED_OUT", (
        f"expected the redriven execution to TIME OUT again unclaimed, got {timed_out_2!r}"
    )

    redrive_2 = sfn.redrive_execution(executionArn=exec_arn)
    after_redrive_2 = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE", "TIMED_OUT"})
    assert after_redrive_2["redriveCount"] == 2, (
        f"expected redriveCount 2 after a second redrive of a re-timed-out execution, got {after_redrive_2!r}"
    )
    assert redrive_2["redriveDate"] != redrive_1["redriveDate"], (
        "the second RedriveExecution call reported the same redriveDate as the first"
    )

    history_3 = _wait_for_event_count(ctx, exec_arn, "ActivityScheduled", 3)
    types_3 = [e["type"] for e in history_3]
    assert types_3.count("ExecutionTimedOut") == 2, f"expected two ExecutionTimedOut, got {types_3!r}"
    assert types_3.count("ExecutionRedriven") == 2, f"expected two ExecutionRedriven, got {types_3!r}"
    redriven_events = [e for e in history_3 if e["type"] == "ExecutionRedriven"]
    assert redriven_events[1]["timestamp"] == redrive_2["redriveDate"], (
        f"second ExecutionRedriven timestamp {redriven_events[1]['timestamp']!r} does not match "
        f"the second RedriveExecution response's redriveDate {redrive_2['redriveDate']!r}"
    )

    final_task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=final_task["taskToken"], output=json.dumps({"resumed": True}))
    final = _wait_for_status(ctx, exec_arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"})
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED after the second redrive's retry, got {final!r}"
    assert final["redriveCount"] == 2, f"expected final redriveCount 2, got {final!r}"
    assert json.loads(final["output"]) == {"resumed": True}, (
        f"expected the real resumed output, got {final.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
