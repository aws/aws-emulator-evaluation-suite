"""jsonata-parallel-evaluation-failure-timing-and-catch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-parallel-evaluation-failure-timing-and-catch"
GROUP = "parallel_state"
SERVICES = ["stepfunctions"]

_EVAL_ERROR = "States.QueryEvaluationError"
_BAD_EXPR = "{% $number($states.input.v) %}"
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
    """A JSONata Parallel's Arguments error fails before any branch runs; the same error in
    Output or Assign fails only after every branch has already succeeded; and a branch's own
    JSONata evaluation error is retried and then caught by States.ALL, unlike States.Runtime.
    """
    role_arn = _create_role(ctx)

    # (a) Arguments evaluates before any branch starts: the branch's own state is never entered.
    before_arn = _create_state_machine(ctx, role_arn, {
        "QueryLanguage": "JSONata",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Arguments": _BAD_EXPR,
                "Branches": [{"StartAt": "B1", "States": {
                    "B1": {"Type": "Pass", "Output": "ran", "End": True}}}],
                "End": True,
            }
        },
    })
    before = _run_to_terminal(ctx, before_arn, {"v": "not-a-number"})
    _assert_eval_failure(before, state="Fan", field="Arguments")
    before_events = _history(ctx, before["executionArn"])
    assert _entered_names(before_events) == ["Fan"], (
        f"an Arguments evaluation error must fail the Parallel before any branch is entered; "
        f"entered states were {_entered_names(before_events)!r}"
    )
    assert _types(before_events) == [
        "ExecutionStarted", "ParallelStateEntered", "EvaluationFailed", "ParallelStateFailed",
        "ExecutionFailed",
    ], f"unexpected history shape for an Arguments-time failure: {_types(before_events)!r}"

    # (b)/(c) Output and Assign evaluate only after every branch has succeeded.
    for is_assign, extra in ((False, {"Output": _BAD_EXPR, "End": True}),
                              (True, {"Assign": {"bad": _BAD_EXPR}, "Next": "After"})):
        field = "Assign/bad" if is_assign else "Output"
        states = {"Fan": {
            "Type": "Parallel",
            "Branches": [{"StartAt": "B1", "States": {
                "B1": {"Type": "Pass", "Output": "ran", "End": True}}}],
            **extra,
        }}
        if is_assign:
            states["After"] = {"Type": "Pass", "End": True}
        sm_arn = _create_state_machine(ctx, role_arn, {
            "QueryLanguage": "JSONata", "StartAt": "Fan", "States": states,
        })
        after = _run_to_terminal(ctx, sm_arn, {"v": "not-a-number"})
        _assert_eval_failure(after, state="Fan", field=field)
        after_events = _history(ctx, after["executionArn"])
        entered = _entered_names(after_events)
        assert entered == ["Fan", "B1"], (
            f"a {field} evaluation error must fail only after the branch ran; entered states "
            f"were {entered!r}"
        )
        assert "PassStateExited" in _types(after_events), (
            f"branch B1 must have run to completion before the {field} error; history types "
            f"were {_types(after_events)!r}"
        )
        assert "After" not in entered, (
            f"a {field} evaluation error must fail the Parallel, never reach 'After'; entered "
            f"{entered!r}"
        )

    # (d) A branch's own JSONata evaluation error is retried (States.ALL) and then caught,
    # unlike a States.Runtime error, which escapes both.
    catch_def = {
        "QueryLanguage": "JSONata",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Branches": [{"StartAt": "Bad", "States": {
                    "Bad": {"Type": "Pass", "Output": _BAD_EXPR, "End": True}}}],
                "Retry": [{"ErrorEquals": ["States.ALL"], "IntervalSeconds": 1, "MaxAttempts": 2,
                           "BackoffRate": 1.0}],
                "Catch": [{"ErrorEquals": ["States.ALL"],
                           "Output": "{% $states.errorOutput %}", "Next": "Caught"}],
                "Next": "Unreachable",
            },
            "Unreachable": {"Type": "Pass", "End": True},
            "Caught": {"Type": "Pass", "End": True},
        },
    }
    catch_arn = _create_state_machine(ctx, role_arn, catch_def)
    caught = _run_to_terminal(ctx, catch_arn, {"v": "not-a-number"})
    assert caught["status"] == "SUCCEEDED", (
        f"States.ALL must retry then catch a branch's JSONata evaluation error, got "
        f"{caught['status']!r} error={caught.get('error')!r} cause={caught.get('cause')!r}"
    )
    out = json.loads(caught["output"])
    assert out.get("Error") == _EVAL_ERROR, (
        f"the Catch output must carry the branch's error name {_EVAL_ERROR!r}, got {out!r}"
    )
    caught_events = _history(ctx, caught["executionArn"])
    bad_entries = [e for e in caught_events if e.get("stateEnteredEventDetails", {}).get("name") == "Bad"]
    assert len(bad_entries) == 3, (
        f"MaxAttempts=2 on top of the first attempt must run the branch 3 times; Bad was entered "
        f"{len(bad_entries)} time(s) in {_types(caught_events)!r}"
    )
    assert "Unreachable" not in _entered_names(caught_events), (
        f"the Catch must route to 'Caught', never past the Parallel's own Next; entered "
        f"{_entered_names(caught_events)!r}"
    )
    eval_failed = [e for e in caught_events if e["type"] == "EvaluationFailed"]
    assert len(eval_failed) == 3, (
        f"each of the 3 attempts must raise its own EvaluationFailed; got {len(eval_failed)}"
    )


# ===== helpers =====
def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnjp-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-behav sfn jsonata parallel execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnjp-sm-")
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


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=90.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} did not reach a terminal status within {timeout_s}s")


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
            return events


def _types(events):
    return [e["type"] for e in events]


def _entered_names(events):
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if "stateEnteredEventDetails" in e]


def _assert_eval_failure(desc, *, state, field):
    assert desc["status"] == "FAILED", (
        f"a JSONata evaluation error in '{field}' of {state!r} must FAIL the execution, got "
        f"{desc['status']!r} output={desc.get('output')!r}"
    )
    assert desc.get("error") == _EVAL_ERROR, (
        f"expected error {_EVAL_ERROR!r}, got {desc.get('error')!r} (cause={desc.get('cause')!r})"
    )
    cause = desc.get("cause") or ""
    expected_cause = (
        f"An error occurred while executing the state '{state}' (entered at the event id #2). "
        f"The JSONata expression '$number($states.input.v)' specified for the field '{field}' "
        "threw an error during evaluation. D3030: Unable to cast value to a number: "
        '"not-a-number"'
    )
    assert cause == expected_cause, f"unexpected cause for field {field!r}: {cause!r}"
    assert desc.get("output") is None, f"a rejected execution must carry no output, got {desc.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
