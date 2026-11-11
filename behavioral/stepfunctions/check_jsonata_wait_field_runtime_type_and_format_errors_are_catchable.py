"""jsonata-wait-field-runtime-type-and-format-errors-are-catchable."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-wait-field-runtime-type-and-format-errors-are-catchable"
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
        Description="sim2real-behav sfn jsonata wait-field execution role",
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


_EVAL_ERROR = "States.QueryEvaluationError"


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
    """A JSONata Wait `Seconds`/`Timestamp` or Task `TimeoutSeconds` of the wrong JSON type, or an
    invalid ISO-8601 `Timestamp`, fails with States.QueryEvaluationError naming the field and the
    type or parse failure -- an ordinary catchable error via States.ALL, not a fatal fault.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-wait-state.html
    """
    role_arn = _create_role(ctx)

    def wait_machine(field, value_expr):
        return {
            "QueryLanguage": "JSONata",
            "StartAt": "W",
            "States": {
                "W": {"Type": "Wait", field: value_expr, "Next": "E"},
                "E": {"Type": "Pass", "End": True},
            },
        }

    seconds_sm = _create_state_machine(
        ctx, wait_machine("Seconds", "{% $states.input.n %}"), role_arn
    )
    exe = _run_to_terminal(ctx, seconds_sm, {"n": "10"})
    assert exe["status"] == "FAILED", f"a string Seconds must FAIL, got {exe['status']!r}"
    assert exe.get("error") == _EVAL_ERROR, f"expected {_EVAL_ERROR!r}, got {exe.get('error')!r}"
    assert exe.get("cause") == (
        "An error occurred while executing the state 'W' (entered at the event id #2). The "
        "JSONata expression '$states.input.n' specified for the field 'Seconds' returned an "
        "unexpected result type. Expected 'number', but was 'string' for value: \"10\""
    ), f"unexpected cause {exe.get('cause')!r}"
    assert "EvaluationFailed" in _event_types(ctx, exe["executionArn"]), (
        "a Seconds type error must record EvaluationFailed in the history"
    )

    timestamp_sm = _create_state_machine(
        ctx, wait_machine("Timestamp", "{% $states.input.t %}"), role_arn
    )
    exe = _run_to_terminal(ctx, timestamp_sm, {"t": 12345})
    assert exe["status"] == "FAILED", f"a numeric Timestamp must FAIL, got {exe['status']!r}"
    assert exe.get("error") == _EVAL_ERROR, f"expected {_EVAL_ERROR!r}, got {exe.get('error')!r}"
    assert exe.get("cause") == (
        "An error occurred while executing the state 'W' (entered at the event id #2). The "
        "JSONata expression '$states.input.t' specified for the field 'Timestamp' returned an "
        "unexpected result type. Expected 'string', but was 'number' for value: 12345"
    ), f"unexpected cause {exe.get('cause')!r}"

    exe = _run_to_terminal(ctx, timestamp_sm, {"t": "2024-11-22"})
    assert exe["status"] == "FAILED", f"a non-ISO-8601 Timestamp must FAIL, got {exe['status']!r}"
    assert exe.get("error") == _EVAL_ERROR, f"expected {_EVAL_ERROR!r}, got {exe.get('error')!r}"
    assert exe.get("cause") == (
        "An error occurred while executing the state 'W' (entered at the event id #2). The "
        "Timestamp field cannot be parsed as an ISO-8601 extended offset date-time format "
        "string: 2024-11-22"
    ), f"unexpected cause {exe.get('cause')!r}"

    # A Task TimeoutSeconds type error is the same error class, and it is catchable.
    timeout_sm = _create_state_machine(
        ctx,
        {
            "QueryLanguage": "JSONata",
            "StartAt": "T",
            "States": {
                "T": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                    "Arguments": {},
                    "TimeoutSeconds": "{% $states.input.t %}",
                    "Catch": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "Output": {"caught": "{% $states.errorOutput.Error %}"},
                            "Next": "Handled",
                        }
                    ],
                    "End": True,
                },
                "Handled": {"Type": "Pass", "End": True},
            },
        },
        role_arn,
    )
    exe = _run_to_terminal(ctx, timeout_sm, {"t": "10"})
    assert exe["status"] == "SUCCEEDED", (
        f"a caught TimeoutSeconds type error must let the execution SUCCEED, got "
        f"{exe['status']!r} error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    assert json.loads(exe["output"]) == {"caught": _EVAL_ERROR}, (
        f"the Catch must see {_EVAL_ERROR!r} as $states.errorOutput.Error, got {exe['output']!r}"
    )

    # Positive control: a numeric Seconds still waits and succeeds.
    control_sm = _create_state_machine(ctx, wait_machine("Seconds", "{% 1 %}"), role_arn)
    exe = _run_to_terminal(ctx, control_sm, {})
    assert exe["status"] == "SUCCEEDED", (
        f"a numeric Seconds control must SUCCEED, got {exe['status']!r} cause={exe.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
