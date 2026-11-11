"""activity-deleted-mid-flight-orphans-its-outstanding-task."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-deleted-mid-flight-orphans-its-outstanding-task"
GROUP = 'activities'
SERVICES = ['stepfunctions']

#: A token whose ACTIVITY was deleted is refused TaskDoesNotExist, not the TaskTimedOut a
#: consumed or aborted-execution token gets; the distinct code tells a worker its queue is gone.
_DELETED_ACTIVITY_CODE = "TaskDoesNotExist"
#: The code DescribeActivity gives for the deleted activity itself, asserted so that "the token
#: was refused" cannot be satisfied by an activity that was never really deleted.
_GONE_ACTIVITY_CODE = "ActivityDoesNotExist"
#: Short enough that the orphaned execution ends inside this check, long enough that the
#: post-delete RUNNING window below is not racing it.
_TASK_TIMEOUT_SECONDS = 30
#: How long the execution is watched after the activity is deleted, before its task clock is
#: allowed to end it.
_ORPHAN_OBSERVATION_S = 10
_SAMPLE_INTERVAL_S = 2
_TIMEOUT_ERROR = "States.Timeout"
_LATE_REPLY = {"orphaned": True}
_CONTROL_REPLY = {"control": "accepted"}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteActivity while a worker holds a task token is accepted (DescribeActivity then fails
    ActivityDoesNotExist), the execution stays RUNNING, the worker's SendTaskSuccess fails
    TaskDoesNotExist, each with the exact message, and only States.Timeout from the claim ends it."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    definition = {
        "Comment": "one activity task whose activity is deleted while the token is outstanding",
        "StartAt": "HandOff",
        "States": {
            "HandOff": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # Positive control first, while the activity still exists: a worker's reply is accepted and
    # reaches the execution's output.
    control_arn = _start_execution(ctx, sm_arn, {"leg": "control"})
    control_task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    sfn.send_task_success(
        taskToken=control_task["taskToken"], output=json.dumps(_CONTROL_REPLY)
    )
    control = _wait_terminal(ctx, control_arn, timeout_s=90)
    assert control["status"] == "SUCCEEDED", (
        f"the control execution ended {control['status']!r} while its activity still existed: "
        f"{control.get('error')!r} / {control.get('cause')!r}"
    )
    assert json.loads(control["output"]) == _CONTROL_REPLY, (
        f"the control execution output was {control['output']!r}, expected {_CONTROL_REPLY!r}"
    )

    # The subject: a worker claims a task, then the activity underneath it is deleted.
    exec_arn = _start_execution(ctx, sm_arn, {"leg": "subject"})
    task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    token = task["taskToken"]

    # The delete is accepted: a target that refuses it fails here.
    sfn.delete_activity(activityArn=activity_arn)
    gone_code, gone_message = _error(lambda: sfn.describe_activity(activityArn=activity_arn))
    assert gone_code == _GONE_ACTIVITY_CODE, (
        f"after DeleteActivity, DescribeActivity was refused {gone_code!r}, expected "
        f"{_GONE_ACTIVITY_CODE!r} — the activity this check needs deleted is still there, so "
        f"nothing below would be about a deleted activity"
    )
    gone_expected = f"Activity Does Not Exist: '{activity_arn}'"
    assert gone_message == gone_expected, f"expected message {gone_expected!r}, got {gone_message!r}"

    # The execution does not notice; sampled across a window rather than read once.
    deadline = time.monotonic() + _ORPHAN_OBSERVATION_S
    samples = 0
    while time.monotonic() < deadline:
        current = sfn.describe_execution(executionArn=exec_arn)
        samples += 1
        assert current["status"] == "RUNNING", (
            f"deleting the activity moved its in-flight execution to {current['status']!r}; "
            f"DeleteActivity must not cancel work already handed to a worker: "
            f"{current.get('error')!r} / {current.get('cause')!r}"
        )
        time.sleep(_SAMPLE_INTERVAL_S)
    assert samples >= 2, f"the orphan window was sampled only {samples!r} times"

    # The worker learns about the deletion only when it reports in.
    code, message = _error(
        lambda: sfn.send_task_success(taskToken=token, output=json.dumps(_LATE_REPLY))
    )
    assert code == _DELETED_ACTIVITY_CODE, (
        f"SendTaskSuccess on the token of a DELETED activity was refused {code!r}, expected "
        f"{_DELETED_ACTIVITY_CODE!r}. A token whose activity is gone must not be reported the "
        f"same way as one that merely expired or was already consumed"
    )
    expected = f"Activity Does Not Exist: '{activity_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Only the task clock, running from the claim, ends the orphan; the refused reply reached
    # nothing.
    final = _wait_terminal(ctx, exec_arn, timeout_s=_TASK_TIMEOUT_SECONDS + 90)
    assert final["status"] == "FAILED", (
        f"the orphaned execution ended {final['status']!r}; with its activity deleted and its "
        f"worker refused, TimeoutSeconds={_TASK_TIMEOUT_SECONDS!r} is what must close it: "
        f"{final.get('cause')!r}"
    )
    assert final.get("error") == _TIMEOUT_ERROR, (
        f"the orphaned execution failed with error {final.get('error')!r}, expected "
        f"{_TIMEOUT_ERROR!r} — a deletion-specific failure would mean the delete propagated to "
        f"the execution, which it does not"
    )
    assert "output" not in final, (
        f"the refused SendTaskSuccess put an output on the orphaned execution: "
        f"{final.get('output')!r}"
    )

    history = _full_history(ctx, exec_arn)
    types = [e["type"] for e in history]
    started = _one_event(history, "ActivityStarted")
    timed_out = _one_event(history, "ActivityTimedOut")
    assert timed_out["activityTimedOutEventDetails"].get("error") == _TIMEOUT_ERROR, (
        f"ActivityTimedOut recorded error "
        f"{timed_out['activityTimedOutEventDetails'].get('error')!r}, expected {_TIMEOUT_ERROR!r}"
    )
    assert "ActivitySucceeded" not in types, (
        f"the refused SendTaskSuccess appended a success event to the orphaned execution: "
        f"{types!r}"
    )
    assert "ActivityFailed" not in types, (
        f"the history records ActivityFailed, so the deletion was reported into the execution as "
        f"a task failure; real AWS leaves it to the timeout: {types!r}"
    )

    # The clock that closed it ran from the claim, not from the delete. Lower bound only: AWS
    # guarantees a timeout cannot fire early, and promises nothing about detection latency.
    held_s = (timed_out["timestamp"] - started["timestamp"]).total_seconds()
    assert held_s >= _TASK_TIMEOUT_SECONDS, (
        f"ActivityTimedOut landed {held_s!r}s after ActivityStarted, sooner than the "
        f"{_TASK_TIMEOUT_SECONDS!r}s the task was allowed; deleting the activity must not "
        f"shorten the task clock"
    )


# ===== helpers =====
def _error(fn):
    """The AWS error (code, message) `fn` raised. An unexpected success raises, so it can never
    read as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be refused but it succeeded, returning {result!r}"
    )


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
    """An activity whose cleanup tolerates ActivityDoesNotExist: the check body deletes it."""
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"),
        tags=[{"key": "sim2real", "value": "1"}],
    )["activityArn"]

    def _delete_activity():
        try:
            sfn.delete_activity(activityArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ActivityDoesNotExist":
                raise

    ctx.on_cleanup(_delete_activity)
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
