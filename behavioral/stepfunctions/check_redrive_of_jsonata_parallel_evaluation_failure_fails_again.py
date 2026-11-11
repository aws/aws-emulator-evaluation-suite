"""redrive-of-jsonata-parallel-evaluation-failure-fails-again."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-of-jsonata-parallel-evaluation-failure-fails-again"
GROUP = "parallel_state"
SERVICES = ["stepfunctions"]

_EVAL_ERROR = "States.QueryEvaluationError"
_BAD_EXPR = "{% $number('not-a-number') %}"
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
    """RedriveExecution on a Parallel that failed from a JSONata evaluation error re-evaluates
    the same deterministic expression and fails identically: ExecutionRedriven precedes a fresh
    EvaluationFailed, ParallelStateFailed and ExecutionFailed, with the original error and cause.
    """
    role_arn = _create_role(ctx)
    definition = {
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
    }
    sm_arn = _create_state_machine(ctx, role_arn, definition)
    exec_arn = _start(ctx, sm_arn)

    first = _wait_terminal(ctx, exec_arn)
    assert (first["status"], first.get("redriveStatus"), first.get("redriveCount", 0)) == (
        "FAILED", "REDRIVABLE", 0), (
        f"the original execution must be FAILED and REDRIVABLE with redriveCount 0, got "
        f"status={first['status']!r} redriveStatus={first.get('redriveStatus')!r} "
        f"redriveCount={first.get('redriveCount')!r}"
    )
    assert first.get("error") == _EVAL_ERROR, (
        f"expected error {_EVAL_ERROR!r}, got {first.get('error')!r} (cause={first.get('cause')!r})"
    )
    original_cause = first.get("cause")

    ctx.client("stepfunctions").redrive_execution(executionArn=exec_arn)
    second = _wait_terminal(ctx, exec_arn)
    assert (second["status"], second.get("redriveStatus"), second.get("redriveCount")) == (
        "FAILED", "REDRIVABLE", 1), (
        f"the redriven execution must FAIL again, still REDRIVABLE, with redriveCount 1, got "
        f"status={second['status']!r} redriveStatus={second.get('redriveStatus')!r} "
        f"redriveCount={second.get('redriveCount')!r}"
    )
    assert second.get("error") == _EVAL_ERROR, (
        f"the redriven run must fail with the same error {_EVAL_ERROR!r}, got "
        f"{second.get('error')!r}"
    )
    assert second.get("cause") == original_cause, (
        f"re-evaluating the same deterministic JSONata expression must reproduce the same "
        f"cause; first was {original_cause!r}, redriven was {second.get('cause')!r}"
    )
    assert second.get("output") is None, (
        f"a failed redriven execution must carry no output, got {second.get('output')!r}"
    )

    events = _history(ctx, exec_arn)
    types = _types(events)
    assert types == [
        "ExecutionStarted", "ParallelStateEntered", "EvaluationFailed", "ParallelStateFailed",
        "ExecutionFailed", "ExecutionRedriven", "EvaluationFailed", "ParallelStateFailed",
        "ExecutionFailed",
    ], f"unexpected redrive history shape: {types!r}"
    redriven = [e["executionRedrivenEventDetails"]["redriveCount"] for e in events
                if e["type"] == "ExecutionRedriven"]
    assert redriven == [1], f"ExecutionRedriven must carry redriveCount 1, got {redriven!r}"
    assert "B1" not in [e.get("stateEnteredEventDetails", {}).get("name") for e in events], (
        "the branch must never run: the Arguments error fails the Parallel before any branch "
        "is entered, on both the original run and the redrive"
    )


# ===== helpers =====
def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnredr-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-behav sfn jsonata-redrive execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnredr-sm-")
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


def _start(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


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
