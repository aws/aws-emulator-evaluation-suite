"""activity-heartbeat-timeout-closes-task-before-task-timeout."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-heartbeat-timeout-closes-task-before-task-timeout"
GROUP = 'activities'
SERVICES = ['stepfunctions']

#: Two clocks on one Task state, an order of magnitude apart. The gap is the whole point: a
#: target that only implements TimeoutSeconds cannot end the execution inside the heartbeat
#: window, and a target that implements neither cannot end it at all.
_HEARTBEAT_SECONDS = 5
_TASK_TIMEOUT_SECONDS = 120
#: The ASL error name real AWS reports when the heartbeat window lapses.
_TIMEOUT_ERROR = "States.Timeout"
_CONTROL_REPLY = {"kept_alive": True}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A claimed activity task whose worker stops heartbeating fails States.Timeout on the
    HEARTBEAT clock, before TimeoutSeconds could fire; a worker that keeps heartbeating succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    definition = {
        "Comment": "one activity task carrying both a heartbeat clock and a task clock",
        "StartAt": "HandOff",
        "States": {
            "HandOff": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                "HeartbeatSeconds": _HEARTBEAT_SECONDS,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # Positive control first: a worker that keeps heartbeating outlives several heartbeat
    # windows and completes normally. Without it, "the execution failed" would be
    # indistinguishable from "a task with HeartbeatSeconds set can never succeed here".
    control_arn = _start_execution(ctx, sm_arn, {"leg": "control"})
    control_task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    control_token = control_task["taskToken"]
    beats = 0
    alive_until = time.monotonic() + (_HEARTBEAT_SECONDS * 2)
    while time.monotonic() < alive_until:
        sfn.send_task_heartbeat(taskToken=control_token)
        beats += 1
        time.sleep(_HEARTBEAT_SECONDS / 2.5)
    assert beats >= 2, f"the control worker sent only {beats!r} heartbeats; it must send several"
    running = sfn.describe_execution(executionArn=control_arn)
    assert running["status"] == "RUNNING", (
        f"the heartbeated control execution was {running['status']!r} after more than "
        f"{_HEARTBEAT_SECONDS!r}s of heartbeats; heartbeats must reset the clock: "
        f"{running.get('error')!r} / {running.get('cause')!r}"
    )
    sfn.send_task_success(taskToken=control_token, output=json.dumps(_CONTROL_REPLY))
    control = _wait_terminal(ctx, control_arn, timeout_s=90)
    assert control["status"] == "SUCCEEDED", (
        f"the heartbeated control execution ended {control['status']!r}: "
        f"{control.get('error')!r} / {control.get('cause')!r}"
    )
    assert json.loads(control["output"]) == _CONTROL_REPLY, (
        f"the control execution output was {control['output']!r}, expected {_CONTROL_REPLY!r}"
    )

    # The subject: claim the task, then go silent.
    exec_arn = _start_execution(ctx, sm_arn, {"leg": "silent"})
    task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    assert task.get("taskToken"), f"the silent worker was handed no task token: {task!r}"

    final = _wait_terminal(ctx, exec_arn, timeout_s=_TASK_TIMEOUT_SECONDS + 60)
    assert final["status"] == "FAILED", (
        f"a claimed task whose worker never heartbeated left the execution "
        f"{final['status']!r}: {final.get('cause')!r}"
    )
    assert final.get("error") == _TIMEOUT_ERROR, (
        f"the execution failed with error {final.get('error')!r}, expected the documented "
        f"{_TIMEOUT_ERROR!r} for a lapsed heartbeat window"
    )
    assert "output" not in final, (
        f"a heartbeat-timed-out execution carries an output: {final.get('output')!r}"
    )

    history = _full_history(ctx, exec_arn)
    types = [e["type"] for e in history]

    scheduled = _one_event(history, "ActivityScheduled")
    details = scheduled["activityScheduledEventDetails"]
    assert details.get("heartbeatInSeconds") == _HEARTBEAT_SECONDS, (
        f"ActivityScheduled recorded heartbeatInSeconds {details.get('heartbeatInSeconds')!r}, "
        f"expected {_HEARTBEAT_SECONDS!r}"
    )
    assert details.get("timeoutInSeconds") == _TASK_TIMEOUT_SECONDS, (
        f"ActivityScheduled recorded timeoutInSeconds {details.get('timeoutInSeconds')!r}, "
        f"expected {_TASK_TIMEOUT_SECONDS!r}"
    )

    started = _one_event(history, "ActivityStarted")
    timed_out = _one_event(history, "ActivityTimedOut")
    recorded_error = timed_out["activityTimedOutEventDetails"].get("error")
    assert recorded_error == _TIMEOUT_ERROR, (
        f"ActivityTimedOut recorded error {recorded_error!r}, expected {_TIMEOUT_ERROR!r}"
    )

    # The discriminating assertion, expressed as an ordering rather than a duration: the task was
    # closed before its own TimeoutSeconds could have expired, so the clock that closed it was
    # the heartbeat clock. No upper bound tighter than TimeoutSeconds is asserted, because AWS
    # guarantees no detection latency.
    held_s = (timed_out["timestamp"] - started["timestamp"]).total_seconds()
    assert _HEARTBEAT_SECONDS <= held_s < _TASK_TIMEOUT_SECONDS, (
        f"the task was held {held_s!r}s between ActivityStarted and ActivityTimedOut; the "
        f"heartbeat clock ({_HEARTBEAT_SECONDS!r}s) must close it no sooner than one whole "
        f"heartbeat window and strictly before its task timeout ({_TASK_TIMEOUT_SECONDS!r}s) is "
        f"reachable, otherwise the failure is not attributable to the heartbeat at all"
    )

    assert "ActivitySucceeded" not in types, (
        f"the history of a heartbeat-timed-out task carries ActivitySucceeded: {types!r}"
    )


# ===== helpers =====
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
    deadline = time.monotonic() + 90.0
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
            time.sleep(3)
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
    deadline = time.monotonic() + timeout_s
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
    deadline = time.monotonic() + timeout_s
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
