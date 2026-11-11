"""redrive-execution-resumes-from-aborted-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-resumes-from-aborted-status"
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on an ABORTED execution reschedules a fresh activity task and
    redriveCount climbs across two abort/redrive cycles, and the pre-redrive task
    token stops working once the new task has been scheduled.
    """
    sfn = ctx.client("stepfunctions")
    activity_arn = _create_activity(ctx)
    role_arn = _create_sfn_role(ctx)
    definition = {
        "Comment": "one activity task with no timeout pressure",
        "StartAt": "T",
        "States": {"T": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": 300, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn = _start_execution(ctx, sm_arn)

    stale_task = _poll_activity_task(ctx, activity_arn)
    sfn.stop_execution(executionArn=exec_arn)
    aborted = _wait_for_status(ctx, exec_arn, {"ABORTED"})
    assert aborted["status"] == "ABORTED", f"expected ABORTED after StopExecution, got {aborted!r}"

    history_1 = [e["type"] for e in _full_history(ctx, exec_arn)]
    assert history_1.index("ActivityScheduled") < history_1.index("ExecutionAborted"), (
        f"expected ActivityScheduled before ExecutionAborted, got {history_1!r}"
    )

    redrive_1 = sfn.redrive_execution(executionArn=exec_arn)
    after_redrive_1 = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE"})
    assert after_redrive_1["redriveCount"] == 1, (
        f"expected redriveCount 1 after the first RedriveExecution, got {after_redrive_1!r}"
    )

    history_2 = _wait_for_event_count(ctx, exec_arn, "ActivityScheduled", 2)
    types_2 = [e["type"] for e in history_2]
    assert types_2.count("ExecutionRedriven") == 1, f"expected one ExecutionRedriven, got {types_2!r}"
    assert types_2.index("ExecutionAborted") < types_2.index("ExecutionRedriven") \
        < list_second_index(types_2, "ActivityScheduled"), (
        f"expected Aborted -> ExecutionRedriven -> (new) ActivityScheduled in that order, got {types_2!r}"
    )
    redriven_event = [e for e in history_2 if e["type"] == "ExecutionRedriven"][0]
    assert redriven_event["timestamp"] == redrive_1["redriveDate"], (
        f"ExecutionRedriven timestamp {redriven_event['timestamp']!r} does not match the "
        f"RedriveExecution response's redriveDate {redrive_1['redriveDate']!r}"
    )

    try:
        sfn.send_task_success(taskToken=stale_task["taskToken"], output=json.dumps({"late": True}))
        raise AssertionError("the pre-redrive task token was accepted after redrive rescheduled a new task")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg = exc.response["Error"]["Message"]
        assert code == "TaskTimedOut", f"expected TaskTimedOut on the stale token, got {code!r}: {msg!r}"
        expected_msg = f"Task Timed Out: '{activity_arn}'"
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    second_task = _poll_activity_task(ctx, activity_arn)
    assert second_task["taskToken"] != stale_task["taskToken"], (
        "the redrive handed out the SAME task token the stale one already failed on"
    )
    sfn.stop_execution(executionArn=exec_arn)
    aborted_2 = _wait_for_status(ctx, exec_arn, {"ABORTED"})
    assert aborted_2["redriveCount"] == 1, (
        f"a second StopExecution must not change redriveCount, got {aborted_2!r}"
    )

    redrive_2 = sfn.redrive_execution(executionArn=exec_arn)
    after_redrive_2 = _wait_for_status(ctx, exec_arn, {"RUNNING", "PENDING_REDRIVE"})
    assert after_redrive_2["redriveCount"] == 2, (
        f"expected redriveCount 2 after a second abort/redrive cycle, got {after_redrive_2!r}"
    )

    history_3 = [e["type"] for e in _wait_for_event_count(ctx, exec_arn, "ActivityScheduled", 3)]
    assert history_3.count("ExecutionAborted") == 2, f"expected two ExecutionAborted, got {history_3!r}"
    assert history_3.count("ExecutionRedriven") == 2, f"expected two ExecutionRedriven, got {history_3!r}"
    assert redrive_2["redriveDate"] != redrive_1["redriveDate"], (
        "the second RedriveExecution call reported the same redriveDate as the first"
    )

    final_task = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=final_task["taskToken"], output=json.dumps({"resumed": True}))
    final = _wait_for_status(ctx, exec_arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"})
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED after the second redrive's retry, got {final!r}"
    assert final["redriveCount"] == 2, f"expected final redriveCount 2, got {final!r}"
    assert json.loads(final["output"]) == {"resumed": True}, (
        f"expected the real resumed output, got {final.get('output')!r}"
    )


def list_second_index(items, value):
    """The index of the SECOND occurrence of ``value`` in ``items``."""
    first = items.index(value)
    return items.index(value, first + 1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
