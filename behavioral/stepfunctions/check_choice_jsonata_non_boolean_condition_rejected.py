"""choice-jsonata-non-boolean-condition-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-jsonata-non-boolean-condition-rejected"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _execution_role(ctx):
    """A throwaway execution role, so the check assumes no pre-existing estate."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-choice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choice: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choice"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine is what makes this correct, and this sleep only makes it cheaper.
    time.sleep(2)
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-choice-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "choice"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_and_wait(ctx, sm_arn, input_data, *, timeout_s=60):
    """Start one execution, wait for a terminal status, return (describe, execution arn)."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-choice-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(
            f"execution for input {input_data!r} never reached a terminal status within "
            f"{timeout_s}s; last describe was {desc!r}"
        )
    return desc, exec_arn


def _history(ctx, exec_arn):
    """The full, paginated execution history."""
    sfn = ctx.client("stepfunctions")
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
    return events


def _entered(events):
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if "stateEnteredEventDetails" in e
    ]


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


_EVAL_ERROR = "States.QueryEvaluationError"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A JSONata Choice Condition evaluating to a non-boolean (string, number, undefined) fails
    the execution with States.QueryEvaluationError naming the field and type, never Default.
    Boolean controls before and after prove the machine routes and is not poisoned.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html
    """
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(
        ctx,
        {
            "QueryLanguage": "JSONata",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    # The Condition's value type is whatever $.label happens to be.
                    "Choices": [{"Condition": "{% $states.input.label %}", "Next": "Matched"}],
                    "Default": "Fallback",
                },
                "Matched": {"Type": "Pass", "Output": "matched", "End": True},
                "Fallback": {"Type": "Pass", "Output": "fell-back", "End": True},
            },
        },
        role_arn,
    )

    def assert_routes(label_value, expected_output, expected_state):
        desc, exec_arn = _start_and_wait(ctx, sm_arn, {"label": label_value})
        assert desc["status"] == "SUCCEEDED", (
            f"control with a boolean label={label_value!r} must succeed, got "
            f"status={desc.get('status')} error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert _output(desc) == expected_output, (
            f"control with label={label_value!r} must produce {expected_output!r}, got "
            f"{_output(desc)!r}"
        )
        entered = _entered(_history(ctx, exec_arn))
        assert entered == ["Route", expected_state], (
            f"control with label={label_value!r} must enter ['Route', {expected_state!r}], "
            f"history entered {entered!r}"
        )

    assert_routes(True, "matched", "Matched")
    assert_routes(False, "fell-back", "Fallback")

    # Only the JSON type of $.label varies; a naive implementation coerces these by truthiness.
    rejections = [
        ("hello", "string", "a string is truthy in every host language JSONata resembles"),
        (1, "number", "a non-zero number is truthy in every host language JSONata resembles"),
    ]
    causes = {}
    for label_value, expected_type, why in rejections:
        desc, exec_arn = _start_and_wait(ctx, sm_arn, {"label": label_value})

        assert desc["status"] == "FAILED", (
            f"a Condition evaluating to a {expected_type} must FAIL the execution rather than "
            f"being coerced or treated as no-match; label={label_value!r} gave "
            f"status={desc.get('status')} output={desc.get('output')!r} -- {why}"
        )
        assert desc.get("error") == _EVAL_ERROR, (
            f"expected error {_EVAL_ERROR!r} for a {expected_type} Condition, got "
            f"{desc.get('error')!r} (cause={desc.get('cause')!r})"
        )
        cause = desc.get("cause") or ""
        assert "Choices[0]/Condition" in cause, (
            f"the cause must name the field whose expression misevaluated, so a caller can find "
            f"it in a definition with many Choices; got {cause!r}"
        )
        assert "Expected 'boolean'" in cause, (
            f"the cause must say a boolean was required; got {cause!r}"
        )
        assert f"but was '{expected_type}'" in cause, (
            f"the cause must report the type actually produced ({expected_type!r}), which is what "
            f"makes the message actionable; got {cause!r}"
        )
        causes[expected_type] = cause

        assert desc.get("output") is None, (
            f"a rejected execution must carry no output, got {desc.get('output')!r}"
        )
        events = _history(ctx, exec_arn)
        entered = _entered(events)
        assert entered == ["Route"], (
            f"a non-boolean Condition must enter the Choice state and stop there; neither "
            f"'Matched' nor 'Fallback' may be entered. History entered {entered!r} -- falling "
            f"through to 'Fallback' here would be a silent success on a broken workflow."
        )
        types = [e["type"] for e in events]
        assert "EvaluationFailed" in types, (
            f"the history must carry an EvaluationFailed event naming the failed expression; "
            f"event types were {types}"
        )
        failed = [e for e in events if e["type"] == "ExecutionFailed"]
        assert failed, f"the history must contain ExecutionFailed; event types were {types}"
        details = failed[-1].get("executionFailedEventDetails", {})
        assert details.get("error") == _EVAL_ERROR, (
            f"ExecutionFailed must name {_EVAL_ERROR!r}, got {details!r}"
        )
        assert details.get("cause") == cause, (
            f"the history event must carry the same cause DescribeExecution reports; "
            f"DescribeExecution said {cause!r} and the event said {details.get('cause')!r}"
        )

    # An undefined result has its own cause, distinct from the wrong-type message.
    desc, exec_arn = _start_and_wait(ctx, sm_arn, {"other": "no label at all"})
    assert desc["status"] == "FAILED", (
        f"a Condition whose expression resolves to nothing must fail the execution, got "
        f"status={desc.get('status')} output={desc.get('output')!r}"
    )
    assert desc.get("error") == _EVAL_ERROR, (
        f"an undefined Condition result is also {_EVAL_ERROR!r}, got {desc.get('error')!r} "
        f"(cause={desc.get('cause')!r})"
    )
    undefined_cause = desc.get("cause") or ""
    assert "returned nothing (undefined)" in undefined_cause, (
        f"the cause must say the expression returned nothing, which is a different diagnosis "
        f"from a wrong result type; got {undefined_cause!r}"
    )
    assert undefined_cause not in causes.values(), (
        f"an undefined result and a wrong-typed result are different failures and must not "
        f"collapse into one byte-identical cause; got {undefined_cause!r} for both"
    )
    assert desc.get("output") is None, (
        f"a rejected execution must carry no output, got {desc.get('output')!r}"
    )
    undefined_entered = _entered(_history(ctx, exec_arn))
    assert undefined_entered == ["Route"], (
        f"an undefined Condition must not enter either branch target; history entered "
        f"{undefined_entered!r}"
    )

    assert_routes(True, "matched", "Matched")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
