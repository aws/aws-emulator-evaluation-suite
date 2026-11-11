"""jsonata-task-error-two-levels-deep-propagates-through-map-and-parallel."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-task-error-two-levels-deep-propagates-through-map-and-parallel"
GROUP = "parallel_state"
SERVICES = ["stepfunctions"]

_EVAL_ERROR = "States.QueryEvaluationError"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A JSONata Task error two containers deep (inside a Map inside a Parallel branch) climbs
    EvaluationFailed, MapIterationFailed, TaskStateAborted (the sibling branch's in-flight Task),
    MapStateFailed, ExecutionFailed, and the cause names the failing Task's own entered-event id.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)
    activity_arn = _create_activity(ctx)

    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "TheMap",
                        "States": {
                            "TheMap": {
                                "Type": "Map",
                                "Items": [1],
                                "ItemProcessor": {
                                    "ProcessorConfig": {"Mode": "INLINE"},
                                    "StartAt": "Delay",
                                    "States": {
                                        "Delay": {"Type": "Wait", "Seconds": 5, "Next": "BadTask"},
                                        "BadTask": {
                                            "Type": "Task",
                                            "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                                            "Arguments": "{% $number('not-a-number') %}",
                                            "End": True,
                                        },
                                    },
                                },
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "SlowTask",
                        "States": {
                            "SlowTask": {"Type": "Task", "Resource": activity_arn, "End": True}
                        },
                    },
                ],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, role_arn, definition)
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))

    # Claim the sibling branch's activity task so it is genuinely in flight when the Map's
    # Task fails two levels down, proving the abort reaches a claimed, not merely scheduled, task.
    _poll_activity_task(ctx, activity_arn)

    desc = _wait_terminal(ctx, exec_arn)
    events = _history(ctx, exec_arn)
    types = _types(events)

    assert desc["status"] == "FAILED", (
        f"the nested Task error must fail the whole execution, got {desc['status']!r} "
        f"output={desc.get('output')!r}"
    )
    assert desc.get("error") == _EVAL_ERROR, (
        f"expected error {_EVAL_ERROR!r}, got {desc.get('error')!r} (cause={desc.get('cause')!r})"
    )

    bad_task_entered = [e for e in events
                        if e.get("stateEnteredEventDetails", {}).get("name") == "BadTask"]
    assert len(bad_task_entered) == 1, (
        f"'BadTask' must be entered exactly once; got {len(bad_task_entered)} in {types!r}"
    )
    bad_task_id = bad_task_entered[0]["id"]
    expected_cause = (
        f"An error occurred while executing the state 'BadTask' (entered at the event id "
        f"#{bad_task_id}). The JSONata expression '$number('not-a-number')' specified for the "
        "field 'Arguments' threw an error during evaluation. D3030: Unable to cast value to a "
        'number: "not-a-number"'
    )
    assert desc.get("cause") == expected_cause, (
        f"the cause must name BadTask's own entered-event id (#{bad_task_id}); got "
        f"{desc.get('cause')!r}"
    )

    def first_index(event_type):
        for i, t in enumerate(types):
            if t == event_type:
                return i
        raise AssertionError(f"{event_type!r} missing from history {types!r}")

    order = [first_index(t) for t in
             ("EvaluationFailed", "MapIterationFailed", "TaskStateAborted", "MapStateFailed",
              "ExecutionFailed")]
    assert order == sorted(order), (
        f"the propagation chain must appear in order EvaluationFailed, MapIterationFailed, "
        f"TaskStateAborted, MapStateFailed, ExecutionFailed; full history was {types!r}"
    )

    # The sibling branch's Task was claimed (ActivityStarted) but never completed: it was
    # aborted by the Map's failure, not by reaching its own end.
    assert "ActivityStarted" in types, f"SlowTask's activity must have been claimed; {types!r}"
    task_aborted_count = sum(1 for e in events if e["type"] == "TaskStateAborted")
    assert task_aborted_count == 2, (
        f"both the failing Task (BadTask) and its sibling branch's Task (SlowTask) must be "
        f"reported aborted; TaskStateAborted appeared {task_aborted_count} time(s) in {types!r}"
    )
    assert desc.get("output") is None, f"a failed execution must carry no output, got {desc.get('output')!r}"


# ===== helpers =====
def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnnest-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-behav sfn nested-propagation execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-sfnnest-act-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnnest-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _poll_activity_task(ctx, activity_arn, timeout_s=90.0):
    """GetActivityTask long-polls (up to ~60 s per call); loop until a task arrives."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav")
        if resp.get("taskToken"):
            return resp["taskToken"], resp.get("input")
    raise AssertionError(f"no activity task arrived on {activity_arn!r} within {timeout_s}s")


def _wait_terminal(ctx, exec_arn, *, timeout_s=90.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return sorted(events, key=lambda e: e["id"])


def _types(events):
    return [e["type"] for e in events]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
