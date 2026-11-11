"""activity-stopped-execution-refuses-its-outstanding-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-stopped-execution-refuses-its-outstanding-token"
GROUP = 'activities'
SERVICES = ['stepfunctions']

_TASK_TIMEOUT_SECONDS = 180
#: A token whose execution was stopped is refused TaskTimedOut, the same code a consumed or
#: expired token gets, so a worker cannot tell "too slow" from "execution aborted".
_DEAD_TOKEN_CODE = "TaskTimedOut"
_STOP_ERROR = "OperatorStop"
_STOP_CAUSE = "stopped while the activity task was outstanding"
_LATE_REPLY = {"late": True}
_CONTROL_REPLY = {"control": "accepted"}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """StopExecution while an activity task is outstanding kills its token: the worker's
    SendTaskSuccess fails TaskTimedOut with the exact message, and the ABORTED execution keeps the
    stopper's error and cause with no output. A never-stopped control on the same wiring runs first."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    definition = {
        "Comment": "one activity task whose execution is stopped while the token is outstanding",
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

    # Positive control first, same state machine and same activity: an execution nobody stops
    # accepts the worker's reply.
    control_arn = _start_execution(ctx, sm_arn, {"leg": "control"})
    control_task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    sfn.send_task_success(
        taskToken=control_task["taskToken"], output=json.dumps(_CONTROL_REPLY)
    )
    control = _wait_terminal(ctx, control_arn, timeout_s=90)
    assert control["status"] == "SUCCEEDED", (
        f"the un-stopped control execution ended {control['status']!r}: "
        f"{control.get('error')!r} / {control.get('cause')!r}"
    )
    assert json.loads(control["output"]) == _CONTROL_REPLY, (
        f"the control execution output was {control['output']!r}, expected {_CONTROL_REPLY!r}"
    )

    # The subject: a worker claims the task, and the execution is stopped while it holds the token.
    exec_arn = _start_execution(ctx, sm_arn, {"leg": "subject"})
    task = _poll_activity_task(
        ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
    )
    token = task["taskToken"]
    sfn.stop_execution(executionArn=exec_arn, error=_STOP_ERROR, cause=_STOP_CAUSE)

    stopped = _wait_terminal(ctx, exec_arn, timeout_s=90)
    assert stopped["status"] == "ABORTED", (
        f"a stopped execution ended {stopped['status']!r}, expected 'ABORTED': "
        f"{stopped.get('error')!r} / {stopped.get('cause')!r}"
    )
    assert stopped.get("error") == _STOP_ERROR, (
        f"the aborted execution error was {stopped.get('error')!r}, expected the stopper's "
        f"{_STOP_ERROR!r} verbatim"
    )
    assert stopped.get("cause") == _STOP_CAUSE, (
        f"the aborted execution cause was {stopped.get('cause')!r}, expected the stopper's "
        f"{_STOP_CAUSE!r} verbatim"
    )

    # The rejection: the worker still holds a token that now names nothing runnable.
    code, message = _error(
        lambda: sfn.send_task_success(taskToken=token, output=json.dumps(_LATE_REPLY))
    )
    assert code == _DEAD_TOKEN_CODE, (
        f"SendTaskSuccess on the token of an ABORTED execution was refused {code!r}, expected "
        f"{_DEAD_TOKEN_CODE!r}"
    )
    expected = f"Task Timed Out: '{activity_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The effect is absent: the reply reached nothing.
    after = sfn.describe_execution(executionArn=exec_arn)
    assert after["status"] == "ABORTED", (
        f"the refused SendTaskSuccess moved the aborted execution to {after['status']!r}"
    )
    assert "output" not in after, (
        f"the refused SendTaskSuccess wrote an output onto an ABORTED execution: "
        f"{after.get('output')!r}"
    )
    assert after.get("error") == _STOP_ERROR and after.get("cause") == _STOP_CAUSE, (
        f"the refused SendTaskSuccess rewrote the abort to {after.get('error')!r} / "
        f"{after.get('cause')!r}; it must still be {_STOP_ERROR!r} / {_STOP_CAUSE!r}"
    )

    types = [e["type"] for e in _full_history(ctx, exec_arn)]
    assert "ExecutionAborted" in types, (
        f"the history of a stopped execution records no ExecutionAborted: {types!r}"
    )
    assert "ActivityScheduled" in types, (
        f"the history records no ActivityScheduled, so this execution never had an outstanding "
        f"activity task and the check proved nothing: {types!r}"
    )
    # Nothing about the refused reply may appear. ActivityStarted is not asserted either way: the
    # stop can land before the claim is journalled, and AWS may then omit it.
    assert "ActivitySucceeded" not in types, (
        f"the refused SendTaskSuccess appended a success event to an aborted execution: {types!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
