"""activity-worker-input-and-reply-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-worker-input-and-reply-round-trip"
GROUP = 'activities'
SERVICES = ['stepfunctions']

#: The transform the Task state applies before the worker ever sees the payload. The
#: execution input carries a sibling key the Parameters block does not select, so "the worker
#: received the right thing" and "the worker received the whole execution input" are
#: distinguishable outcomes rather than the same one.
_PARAMETERS = {
    "orderId.$": "$.order.id",
    "units.$": "$.order.units",
    "stamp": "constant-from-the-definition",
}
_EXECUTION_INPUT = {
    "order": {"id": "A-17", "units": 3},
    "internal": {"note": "not selected by Parameters, must not reach the worker"},
}
_EXPECTED_WORKER_INPUT = {
    "orderId": "A-17",
    "units": 3,
    "stamp": "constant-from-the-definition",
}
_WORKER_REPLY = {"receipt": "A-17/ok", "units": 6}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The activity worker receives the Parameters-transformed input, and the reply it returns
    becomes the execution's output, asserted on both sides and in the execution history.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    definition = {
        "Comment": "one activity task whose input the interpreter transforms first",
        "StartAt": "HandOff",
        "States": {
            "HandOff": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": 120,
                "Parameters": dict(_PARAMETERS),
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn = _start_execution(ctx, sm_arn, _EXECUTION_INPUT)

    worker_name = ctx.unique_name("sim2real-behav-worker-")
    task = _poll_activity_task(ctx, activity_arn, worker_name=worker_name)
    token = task.get("taskToken")
    assert isinstance(token, str) and token, (
        f"GetActivityTask returned no usable taskToken for a scheduled task: {task!r}"
    )

    delivered = json.loads(task["input"])
    assert delivered == _EXPECTED_WORKER_INPUT, (
        f"the worker was handed {delivered!r}; the Task's Parameters block says it must be "
        f"handed exactly {_EXPECTED_WORKER_INPUT!r}"
    )
    # The absence half: the un-selected sibling key of the execution input must not have
    # travelled. Equality above already implies it; it is asserted separately because a target
    # that forwards the raw execution input instead of the transformed payload is the specific
    # over-permissive failure this check exists to catch.
    assert "internal" not in delivered, (
        f"the raw execution input leaked to the worker: {delivered!r} still carries 'internal', "
        f"which the Parameters block did not select"
    )

    sfn.send_task_success(taskToken=token, output=json.dumps(_WORKER_REPLY))

    final = _wait_terminal(ctx, exec_arn, timeout_s=90)
    assert final["status"] == "SUCCEEDED", (
        f"the execution was {final['status']!r} after the worker reported success: "
        f"{final.get('error')!r} / {final.get('cause')!r}"
    )
    output = json.loads(final["output"])
    assert output == _WORKER_REPLY, (
        f"the execution output was {output!r}; it must be exactly what the worker returned, "
        f"{_WORKER_REPLY!r}"
    )

    history = _full_history(ctx, exec_arn)
    types = [e["type"] for e in history]

    scheduled = _one_event(history, "ActivityScheduled")
    scheduled_input = json.loads(scheduled["activityScheduledEventDetails"]["input"])
    assert scheduled_input == _EXPECTED_WORKER_INPUT, (
        f"ActivityScheduled recorded input {scheduled_input!r}, which disagrees with what the "
        f"worker was handed ({_EXPECTED_WORKER_INPUT!r})"
    )

    started = _one_event(history, "ActivityStarted")
    recorded_worker = started["activityStartedEventDetails"].get("workerName")
    assert recorded_worker == worker_name, (
        f"ActivityStarted recorded workerName {recorded_worker!r}; the poller identified itself "
        f"as {worker_name!r}"
    )

    succeeded = _one_event(history, "ActivitySucceeded")
    succeeded_output = json.loads(succeeded["activitySucceededEventDetails"]["output"])
    assert succeeded_output == _WORKER_REPLY, (
        f"ActivitySucceeded recorded output {succeeded_output!r}, expected the worker's reply "
        f"{_WORKER_REPLY!r}"
    )

    assert "ActivityTimedOut" not in types and "ActivityFailed" not in types, (
        f"the history of a cleanly completed hand-off carries a failure event: {types!r}"
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
