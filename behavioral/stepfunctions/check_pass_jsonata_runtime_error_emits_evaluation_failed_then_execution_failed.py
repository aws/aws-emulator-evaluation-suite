"""pass-jsonata-runtime-error-emits-evaluation-failed-then-execution-failed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pass-jsonata-runtime-error-emits-evaluation-failed-then-execution-failed"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn, name=name, definition=json.dumps(definition), roleArn=_execution_role_arn(ctx),
        type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run(ctx, sm_arn, input_data, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(f"execution for input {input_data!r} never reached terminal: {desc!r}")
    events = []
    token = None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            break
    return desc, events


_EVAL_ERROR = "States.QueryEvaluationError"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A JSONata expression that throws while evaluating a Pass state's Output or Assign field
    fails the execution with States.QueryEvaluationError, naming the field in an EvaluationFailed
    history event followed by an ExecutionFailed event carrying the same cause.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/intrinsic-functions.html
    """
    # Output: the expression itself throws (T2001, the left operand of '+' is not a number),
    # rather than merely evaluating to the wrong type.
    output_definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "P",
        "States": {
            "P": {"Type": "Pass", "Output": "{% $states.input.x + 1 %}", "End": True},
        },
    }
    sm_output = _create_state_machine(ctx, output_definition)

    # Positive control: a numeric x makes the same expression evaluate cleanly.
    desc, _ = _run(ctx, sm_output, {"x": 1})
    assert desc["status"] == "SUCCEEDED", f"the control execution must succeed, got {desc!r}"
    assert json.loads(desc["output"]) == 2, f"expected Output 2, got {desc.get('output')!r}"

    desc, events = _run(ctx, sm_output, {"x": "a"})
    expected_cause = (
        "An error occurred while executing the state 'P' (entered at the event id #2). The "
        "JSONata expression '$states.input.x + 1' specified for the field 'Output' threw an "
        "error during evaluation. T2001: The left side of the \"+\" operator must evaluate to "
        "a number"
    )
    assert desc["status"] == "FAILED", f"a throwing Output expression must FAIL, got {desc!r}"
    assert desc.get("error") == _EVAL_ERROR, f"expected error {_EVAL_ERROR!r}, got {desc.get('error')!r}"
    assert desc.get("cause") == expected_cause, f"expected cause {expected_cause!r}, got {desc.get('cause')!r}"
    assert desc.get("output") is None, f"a failed execution must carry no output, got {desc.get('output')!r}"

    types = [e["type"] for e in events]
    eval_failed = [e for e in events if e["type"] == "EvaluationFailed"]
    assert eval_failed, f"history must carry EvaluationFailed, got types {types!r}"
    details = eval_failed[-1]["evaluationFailedEventDetails"]
    assert (details.get("error"), details.get("cause"), details.get("location"), details.get("state")) == (
        _EVAL_ERROR, expected_cause, "Output", "P",
    ), f"EvaluationFailed details were {details!r}"

    exec_failed = [e for e in events if e["type"] == "ExecutionFailed"]
    assert exec_failed, f"history must carry ExecutionFailed, got types {types!r}"
    exec_details = exec_failed[-1]["executionFailedEventDetails"]
    assert (exec_details.get("error"), exec_details.get("cause")) == (_EVAL_ERROR, expected_cause), (
        f"ExecutionFailed must carry the same error/cause as EvaluationFailed, got {exec_details!r}"
    )
    order = [t for t in types if t in ("EvaluationFailed", "ExecutionFailed")]
    assert order == ["EvaluationFailed", "ExecutionFailed"], f"EvaluationFailed must precede ExecutionFailed: {order!r}"

    # Assign: the same class of runtime error, but in a field with no index of its own (it names
    # the assigned variable instead), proving the claim isn't specific to 'Output'.
    assign_definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "P",
        "States": {
            "P": {
                "Type": "Pass",
                "Assign": {"z": "{% $states.input.x + 1 %}"},
                "Output": "ok",
                "End": True,
            },
        },
    }
    sm_assign = _create_state_machine(ctx, assign_definition)

    desc, _ = _run(ctx, sm_assign, {"x": 1})
    assert desc["status"] == "SUCCEEDED", f"the control execution must succeed, got {desc!r}"

    desc, events = _run(ctx, sm_assign, {"x": "a"})
    expected_assign_cause = (
        "An error occurred while executing the state 'P' (entered at the event id #2). The "
        "JSONata expression '$states.input.x + 1' specified for the field 'Assign/z' threw an "
        "error during evaluation. T2001: The left side of the \"+\" operator must evaluate to "
        "a number"
    )
    assert desc["status"] == "FAILED", f"a throwing Assign expression must FAIL, got {desc!r}"
    assert desc.get("cause") == expected_assign_cause, (
        f"expected cause {expected_assign_cause!r}, got {desc.get('cause')!r}"
    )
    eval_failed = [e for e in events if e["type"] == "EvaluationFailed"]
    assert eval_failed, f"history must carry EvaluationFailed for a throwing Assign expression"
    details = eval_failed[-1]["evaluationFailedEventDetails"]
    assert details.get("location") == "Assign/z", f"expected location 'Assign/z', got {details!r}"
    exec_failed = [e for e in events if e["type"] == "ExecutionFailed"]
    assert exec_failed[-1]["executionFailedEventDetails"].get("cause") == expected_assign_cause, (
        "ExecutionFailed must carry the same cause EvaluationFailed carried"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
