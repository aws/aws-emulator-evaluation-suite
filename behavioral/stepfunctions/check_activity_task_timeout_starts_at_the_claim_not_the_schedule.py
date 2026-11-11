"""activity-task-timeout-starts-at-the-claim-not-the-schedule."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-task-timeout-starts-at-the-claim-not-the-schedule"
GROUP = 'activities'
SERVICES = ['stepfunctions']

#: Small, so the observation window below is a large multiple of it.
_TIMEOUT_SECONDS = 5
#: How long the task is left unclaimed: six times TimeoutSeconds, so a target running the clock
#: from ActivityScheduled would have failed the execution several times over.
_UNCLAIMED_OBSERVATION_S = 30
_SAMPLE_INTERVAL_S = 2
#: The ASL error name real AWS reports when an activity task's TimeoutSeconds elapses.
_TIMEOUT_ERROR = "States.Timeout"
_CONTROL_REPLY = {"claimed_in_time": True}


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An activity task's TimeoutSeconds clock starts at the worker's claim, not at scheduling:
    unclaimed, the task outlives several multiples of its timeout and is still deliverable;
    claimed and abandoned, it fails States.Timeout. A worker that replies completes it.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    definition = {
        "Comment": "one activity task with a short TimeoutSeconds and no heartbeat clock",
        "StartAt": "HandOff",
        "States": {
            "HandOff": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": _TIMEOUT_SECONDS,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn = _start_execution(ctx, sm_arn, {"leg": "unclaimed-then-claimed"})

    # The absence: nobody polls for _UNCLAIMED_OBSERVATION_S. The window is sampled throughout,
    # since a timeout that fired mid-window and one that never fired share the same end state.
    deadline = time.monotonic() + _UNCLAIMED_OBSERVATION_S
    samples = 0
    while time.monotonic() < deadline:
        current = sfn.describe_execution(executionArn=exec_arn)
        samples += 1
        assert current["status"] == "RUNNING", (
            f"the execution went {current['status']!r} after ~"
            f"{_UNCLAIMED_OBSERVATION_S - (deadline - time.monotonic()):.0f}s with NO worker "
            f"ever polling. An unclaimed activity task must not be timed out: "
            f"{current.get('error')!r} / {current.get('cause')!r}"
        )
        time.sleep(_SAMPLE_INTERVAL_S)
    assert samples >= 2, f"the unclaimed window was sampled only {samples!r} times"

    unclaimed_history = _full_history(ctx, exec_arn)
    unclaimed_types = [e["type"] for e in unclaimed_history]
    scheduled = _one_event(unclaimed_history, "ActivityScheduled")
    assert scheduled["activityScheduledEventDetails"].get("timeoutInSeconds") \
        == _TIMEOUT_SECONDS, (
        f"ActivityScheduled recorded timeoutInSeconds "
        f"{scheduled['activityScheduledEventDetails'].get('timeoutInSeconds')!r}, expected "
        f"{_TIMEOUT_SECONDS!r} — the clock this check is about was never armed"
    )
    assert "ActivityTimedOut" not in unclaimed_types, (
        f"the unclaimed task timed out inside the observation window: {unclaimed_types!r}"
    )
    assert "ActivityStarted" not in unclaimed_types, (
        f"the history claims a worker started a task nobody polled for: {unclaimed_types!r}"
    )

    # The task is still live this long after scheduling, so a worker can claim it; once claimed
    # and abandoned, the clock runs.
    claimed = sfn.get_activity_task(
        activityArn=activity_arn, workerName=ctx.unique_name("sim2real-behav-worker-")
    )
    assert claimed.get("taskToken"), (
        f"the task was gone {_UNCLAIMED_OBSERVATION_S!r}s after being scheduled — "
        f"GetActivityTask handed out nothing: {claimed!r}. An unclaimed task must stay "
        f"deliverable, otherwise the work is silently lost"
    )
    delivered = json.loads(claimed["input"])
    assert delivered == {"leg": "unclaimed-then-claimed"}, (
        f"the long-queued task was handed out with input {delivered!r}, not the input the "
        f"execution was started with"
    )

    final = _wait_terminal(ctx, exec_arn, timeout_s=_TIMEOUT_SECONDS + 90)
    assert final["status"] == "FAILED", (
        f"a claimed-then-abandoned task left the execution {final['status']!r}; "
        f"TimeoutSeconds={_TIMEOUT_SECONDS!r} must fail it: {final.get('cause')!r}"
    )
    assert final.get("error") == _TIMEOUT_ERROR, (
        f"the execution failed with error {final.get('error')!r}, expected the documented "
        f"{_TIMEOUT_ERROR!r} for an elapsed activity TimeoutSeconds"
    )
    assert "output" not in final, (
        f"a timed-out execution carries an output: {final.get('output')!r}"
    )

    history = _full_history(ctx, exec_arn)
    types = [e["type"] for e in history]
    started = _one_event(history, "ActivityStarted")
    timed_out = _one_event(history, "ActivityTimedOut")
    recorded_error = timed_out["activityTimedOutEventDetails"].get("error")
    assert recorded_error == _TIMEOUT_ERROR, (
        f"ActivityTimedOut recorded error {recorded_error!r}, expected {_TIMEOUT_ERROR!r}"
    )
    assert "ActivitySucceeded" not in types, (
        f"the history of a timed-out task carries ActivitySucceeded: {types!r}"
    )

    # Where the clock started, read off the two intervals. The lower bound is the direction AWS
    # guarantees (a timeout cannot fire before its own duration has passed); no upper bound on
    # detection latency is asserted, because AWS promises none.
    held_s = (timed_out["timestamp"] - started["timestamp"]).total_seconds()
    assert held_s >= _TIMEOUT_SECONDS, (
        f"ActivityTimedOut landed {held_s!r}s after ActivityStarted, sooner than the "
        f"{_TIMEOUT_SECONDS!r}s the task was allowed to run"
    )
    since_scheduled_s = (timed_out["timestamp"] - scheduled["timestamp"]).total_seconds()
    assert since_scheduled_s > _TIMEOUT_SECONDS * 2, (
        f"the task timed out {since_scheduled_s!r}s after being SCHEDULED, which is not "
        f"distinguishable from a clock that started at schedule time; it was left unclaimed for "
        f"~{_UNCLAIMED_OBSERVATION_S!r}s, so this interval must be far larger than "
        f"{_TIMEOUT_SECONDS!r}s"
    )

    # Positive control, same state machine and timeout: a worker that replies inside the window
    # completes the execution, so the failure above is not "this wiring never works".
    control_arn = _start_execution(ctx, sm_arn, {"leg": "control"})
    control_task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    sfn.send_task_success(
        taskToken=control_task["taskToken"], output=json.dumps(_CONTROL_REPLY)
    )
    control = _wait_terminal(ctx, control_arn, timeout_s=90)
    assert control["status"] == "SUCCEEDED", (
        f"the control execution, whose worker replied in time, ended {control['status']!r}: "
        f"{control.get('error')!r} / {control.get('cause')!r}"
    )
    assert json.loads(control["output"]) == _CONTROL_REPLY, (
        f"the control execution output was {control['output']!r}, expected {_CONTROL_REPLY!r}"
    )


# ===== helpers =====
def _deadline(ctx, timeout_s):
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))



def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role with no permissions attached: an Activity
    task needs none, because the worker calls SendTaskSuccess with its own credentials."""
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
        Description="sim2real-behav sfn activity execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"),
        tags=[{"key": "sim2real", "value": "1"}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD"):
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates (IAM
    exposes no condition to poll for that)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = _deadline(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _start_execution(ctx, sm_arn, input_payload):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll_activity_task(ctx, activity_arn, *, worker_name, timeout_s=120.0):
    """GetActivityTask long-polls ~60 s server-side and returns empty on expiry; re-call it."""
    sfn = ctx.client("stepfunctions")
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn, workerName=worker_name)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(
        f"no activity task was ever handed to a worker within {timeout_s}s; last poll {last!r}"
    )


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


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


def _one_event(history, event_type):
    matching = [e for e in history if e["type"] == event_type]
    assert len(matching) == 1, (
        f"expected exactly one {event_type} event, found {len(matching)!r}; "
        f"history was {[e['type'] for e in history]!r}"
    )
    return matching[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
