"""deep-sfn-language-map-items-path-and-task-timing-path-wrong-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-map-items-path-and-task-timing-path-wrong-type-rejected"
GROUP = "variable_driven_runtime_errors"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Map ItemsPath resolving to a non-array, and a Task HeartbeatSecondsPath or
    TimeoutSecondsPath resolving to a non-numeric value, each fail States.Runtime before any
    iteration or dispatch happens; a well-formed value on the same machine succeeds.
    """
    role_arn = _create_sfn_role(ctx)

    _check_map_items_path(ctx, role_arn)
    _check_task_heartbeat_seconds_path(ctx, role_arn)
    _check_task_timeout_seconds_path(ctx, role_arn)


def _check_map_items_path(ctx, role_arn):
    definition = {"StartAt": "M", "States": {"M": {
        "Type": "Map",
        "ItemsPath": "$.Number",
        "ItemProcessor": {
            "ProcessorConfig": {"Mode": "INLINE"},
            "StartAt": "P",
            "States": {"P": {"Type": "Pass", "End": True}},
        },
        "End": True,
    }}}
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    good = _run_execution(ctx, sm_arn, {"Number": [1, 2, 3]})
    assert good["status"] == "SUCCEEDED", (
        f"control: an ItemsPath pointing at an array must succeed, got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]) == [1, 2, 3], (
        f"control output was {good.get('output')!r}"
    )

    bad = _run_execution(ctx, sm_arn, {"Number": 5})
    assert bad["status"] == "FAILED", f"a non-array ItemsPath must fail, got {bad['status']!r}"
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == 'Reference path "$.Number" must point to array.', (
        f"unexpected ItemsPath rejection cause {bad.get('cause')!r}"
    )
    entered = _entered_names(_history(ctx, bad["executionArn"]))
    assert "P" not in entered, f"no iteration must run on a non-array ItemsPath, entered {entered!r}"


def _check_task_heartbeat_seconds_path(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    activity_name = ctx.unique_name("sim2real-behav-sfnlang-act-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": "sfn-language"}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    definition = {"StartAt": "T", "States": {"T": {
        "Type": "Task",
        "Resource": activity_arn,
        "HeartbeatSecondsPath": "$.hb",
        "TimeoutSeconds": 120,
        "End": True,
    }}}
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # Control: a numeric HeartbeatSecondsPath is accepted and the task is actually dispatched to
    # the activity (it enters RUNNING rather than failing States.Runtime), proven by a worker
    # claiming and completing it.
    exec_arn = _start_execution(ctx, sm_arn, {"hb": 30})
    task = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav-worker")
    assert task.get("taskToken"), (
        f"control: a numeric HeartbeatSecondsPath must let the task reach the activity, "
        f"got no task token (describe={sfn.describe_execution(executionArn=exec_arn)!r})"
    )
    sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps("done"))
    good = _poll_terminal(ctx, exec_arn)
    assert good["status"] == "SUCCEEDED", (
        f"control execution did not succeed: {good['status']!r} error={good.get('error')!r} "
        f"cause={good.get('cause')!r}"
    )

    bad_arn = _start_execution(ctx, sm_arn, {"hb": "not-a-number"})
    bad = _poll_terminal(ctx, bad_arn)
    assert bad["status"] == "FAILED", (
        f"a non-numeric HeartbeatSecondsPath must fail, got {bad['status']!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == (
        "An error occurred while executing the state 'T' (entered at the event id #2). The "
        'HeartbeatSecondsPath parameter cannot be parsed as a long value: $.hb == "not-a-number"'
    ), f"unexpected HeartbeatSecondsPath rejection cause {bad.get('cause')!r}"


def _check_task_timeout_seconds_path(ctx, role_arn):
    definition = {"StartAt": "T", "States": {"T": {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
        "Parameters": {},
        "TimeoutSecondsPath": "$.to",
        "End": True,
    }}}
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # This Task is the first in the suite to have Step Functions actually USE the execution role
    # to call an AWS SDK integration, so its trust can still be propagating.
    good = _run_until_propagated(ctx, sm_arn, {"to": 60})
    assert good["status"] == "SUCCEEDED", (
        f"control: a numeric TimeoutSecondsPath must succeed, got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )

    bad = _run_execution(ctx, sm_arn, {"to": "nope"})
    assert bad["status"] == "FAILED", f"a non-numeric TimeoutSecondsPath must fail, got {bad['status']!r}"
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == (
        "An error occurred while executing the state 'T' (entered at the event id #2). The "
        'TimeoutSecondsPath parameter cannot be parsed as a long value: $.to == "nope"'
    ), f"unexpected TimeoutSecondsPath rejection cause {bad.get('cause')!r}"


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx):
    """An execution role this check owns, shared by the three sibling machines below."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _start_execution(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    return exec_arn


def _poll_terminal(ctx, exec_arn, *, timeout_s=150.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    return _poll_terminal(ctx, _start_execution(ctx, sm_arn, payload), timeout_s=timeout_s)


_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _run_until_propagated(ctx, sm_arn, payload, *, timeout_s=150.0, max_attempts=6):
    """Retry a control execution while the execution role's trust is still propagating through
    IAM at its first real use (CreateStateMachine only checks the role exists, not that Step
    Functions may already use it to call an SDK integration)."""
    last = None
    for _ in range(max_attempts):
        last = _run_execution(ctx, sm_arn, payload, timeout_s=timeout_s)
        blob = (last.get("cause") or "") + (last.get("error") or "")
        if last["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return last
        time.sleep(5)
    return last


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered_names(events):
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
