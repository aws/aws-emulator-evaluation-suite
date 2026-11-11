"""jsonata-task-arguments-evaluating-to-non-object-fails-with-states-runtime."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-task-arguments-evaluating-to-non-object-fails-with-states-runtime"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


# ===== helpers =====
_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata task-arguments execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s=60, max_attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for attempt in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            desc = sfn.describe_execution(executionArn=exec_arn)
            if desc["status"] != "RUNNING":
                break
            time.sleep(1)
        else:
            raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5 + attempt * 3)
    return desc


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _event_types(ctx, exec_arn):
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
            return [e["type"] for e in events]


# ===== end helpers =====


_RUNTIME_ERROR = "States.Runtime"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Task's JSONata `Arguments` that evaluates to a non-object fails with States.Runtime
    naming the value and why, never as a JSONata evaluation error, with no EvaluationFailed history
    event, and uncaught by a States.ALL Catch, unlike an ordinary JSONata evaluation error.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-task-state.html
    """
    role_arn = _create_role(ctx)

    def task_machine(arguments_expr, *, with_catch):
        state = {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
            "Arguments": arguments_expr,
            "End": True,
        }
        if with_catch:
            state["Catch"] = [
                {
                    "ErrorEquals": ["States.ALL"],
                    "Output": {"caught": "{% $states.errorOutput.Error %}"},
                    "Next": "Handled",
                }
            ]
            del state["End"]
            state["Next"] = "NeverHere"
            states = {
                "T": state,
                "NeverHere": {"Type": "Pass", "Output": {"wrong": True}, "End": True},
                "Handled": {"Type": "Pass", "End": True},
            }
        else:
            states = {"T": state}
        return {"QueryLanguage": "JSONata", "StartAt": "T", "States": states}

    sfn = ctx.client("stepfunctions")
    dynamic_string = task_machine("{% $states.input.v %}", with_catch=False)
    v = sfn.validate_state_machine_definition(
        definition=json.dumps(dynamic_string), type="STANDARD"
    )
    assert (v["result"], v["diagnostics"]) == ("OK", []), (
        f"a dynamic Arguments expression is only checked at runtime, got {v!r}"
    )

    string_sm = _create_state_machine(ctx, dynamic_string, role_arn)
    exe = _run_to_terminal(ctx, string_sm, {"v": "hello"})
    assert exe["status"] == "FAILED", f"a string Arguments must FAIL, got {exe['status']!r}"
    assert exe.get("error") == _RUNTIME_ERROR, (
        f"expected {_RUNTIME_ERROR!r}, got {exe.get('error')!r}"
    )
    assert exe.get("cause") == (
        "An error occurred while executing the state 'T' (entered at the event id #2). The "
        "Parameters '\"hello\"' could not be used to start the Task: [The value for the "
        "'Arguments' field cannot be a string]"
    ), f"unexpected cause {exe.get('cause')!r}"
    types = _event_types(ctx, exe["executionArn"])
    assert "EvaluationFailed" not in types, (
        f"a non-object Arguments is a States.Runtime fault, not a JSONata evaluation failure; it "
        f"must carry no EvaluationFailed event, got {types!r}"
    )
    assert types == ["ExecutionStarted", "TaskStateEntered", "ExecutionFailed"], (
        f"unexpected history shape for the uncaught failure: {types!r}"
    )

    array_sm = _create_state_machine(
        ctx, task_machine("{% $states.input.v %}", with_catch=False), role_arn
    )
    exe = _run_to_terminal(ctx, array_sm, {"v": [1, 2, 3]})
    assert exe["status"] == "FAILED", f"an array Arguments must FAIL, got {exe['status']!r}"
    assert exe.get("error") == _RUNTIME_ERROR, (
        f"expected {_RUNTIME_ERROR!r}, got {exe.get('error')!r}"
    )
    assert exe.get("cause") == (
        "An error occurred while executing the state 'T' (entered at the event id #2). The "
        "Parameters '[1,2,3]' could not be used to start the Task: [The value for the "
        "'Arguments' field must be an object]"
    ), f"unexpected cause {exe.get('cause')!r}"

    # Unlike States.QueryEvaluationError, States.Runtime is NOT caught by a States.ALL Catch.
    caught_attempt_sm = _create_state_machine(
        ctx, task_machine("{% $states.input.v %}", with_catch=True), role_arn
    )
    exe = _run_to_terminal(ctx, caught_attempt_sm, {"v": "hello"})
    assert exe["status"] == "FAILED", (
        f"a States.ALL Catch must NOT intercept States.Runtime; expected the execution to still "
        f"FAIL, got {exe['status']!r} output={exe.get('output')!r}"
    )
    assert exe.get("error") == _RUNTIME_ERROR, (
        f"the uncaught error must still be {_RUNTIME_ERROR!r}, got {exe.get('error')!r}"
    )

    # Positive control: an Arguments expression that evaluates to an object runs normally.
    control_sm = _create_state_machine(ctx, task_machine("{% {} %}", with_catch=False), role_arn)
    exe = _run_to_terminal(ctx, control_sm, {})
    assert exe["status"] == "SUCCEEDED", (
        f"an object Arguments control must SUCCEED, got {exe['status']!r} cause={exe.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
