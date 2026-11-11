"""jsonata-fail-and-succeed-evaluate-expressions-undefined-rejected."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "jsonata-fail-and-succeed-evaluate-expressions-undefined-rejected"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


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
    """A throwaway execution role: every state here is Fail/Succeed/Choice, no service call."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-jfs-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-jfs: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "jfs"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-jfs-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "jfs"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_execution(ctx, sm_arn, input_data, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-jfs-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(2)
    raise AssertionError(
        f"execution for input {input_data!r} never reached a terminal status within "
        f"{timeout_s}s; last describe was {desc!r}"
    )


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


_EVAL_ERROR = "States.QueryEvaluationError"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """In JSONata mode, a Fail state's Error/Cause and a Succeed state's Output are each computed
    from expressions, and an expression that resolves to nothing fails with
    States.QueryEvaluationError naming the field and the state."""
    role_arn = _execution_role(ctx)
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Condition": "{% $states.input.case = 'fail-ok' %}", "Next": "FailOk"},
                    {"Condition": "{% $states.input.case = 'fail-bad' %}", "Next": "FailBad"},
                    {"Condition": "{% $states.input.case = 'succeed-ok' %}", "Next": "SucceedOk"},
                    {"Condition": "{% $states.input.case = 'succeed-bad' %}", "Next": "SucceedBad"},
                ],
                "Default": "Fallback",
            },
            "FailOk": {
                "Type": "Fail",
                "Error": "{% 'Code-' & $states.input.code %}",
                "Cause": "{% 'Cause-' & $states.input.detail %}",
            },
            "FailBad": {
                "Type": "Fail",
                "Error": "{% 'Code-' & $states.input.code %}",
                "Cause": "{% $states.input.missing.deep %}",
            },
            "SucceedOk": {
                "Type": "Succeed",
                "Output": {"doubled": "{% $states.input.n * 2 %}"},
            },
            "SucceedBad": {
                "Type": "Succeed",
                "Output": {"doubled": "{% $states.input.missing.deep %}"},
            },
            "Fallback": {"Type": "Fail", "Error": "Unreached", "Cause": "unreached"},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # --- Fail: Error/Cause computed from expressions over real input values -----------------
    fail_ok = _run_execution(ctx, sm_arn, {"case": "fail-ok", "code": "42", "detail": "boom"})
    assert fail_ok["status"] == "FAILED", (
        f"a Fail state must end the execution FAILED; got {fail_ok['status']!r}"
    )
    assert fail_ok.get("error") == "Code-42", (
        f"Fail's Error expression must evaluate against the real input; expected 'Code-42', got "
        f"{fail_ok.get('error')!r}"
    )
    assert fail_ok.get("cause") == "Cause-boom", (
        f"Fail's Cause expression must evaluate against the real input; expected 'Cause-boom', "
        f"got {fail_ok.get('cause')!r}"
    )

    # --- Succeed: Output computed from an expression, execution SUCCEEDED -------------------
    succeed_ok = _run_execution(ctx, sm_arn, {"case": "succeed-ok", "n": 10})
    assert succeed_ok["status"] == "SUCCEEDED", (
        f"a Succeed state must end the execution SUCCEEDED; got {succeed_ok['status']!r}"
    )
    assert _output(succeed_ok) == {"doubled": 20}, (
        f"Succeed's Output expression must evaluate against the real input; expected "
        f"{{'doubled': 20}}, got {_output(succeed_ok)!r}"
    )

    # --- Fail: Cause expression resolves to nothing -> States.QueryEvaluationError ----------
    fail_bad = _run_execution(ctx, sm_arn, {"case": "fail-bad", "code": "42"})
    assert fail_bad["status"] == "FAILED", (
        f"an undefined Cause expression must still fail the execution; got {fail_bad['status']!r}"
    )
    assert fail_bad.get("error") == _EVAL_ERROR, (
        f"an undefined expression result in a Fail field must report {_EVAL_ERROR!r}, got "
        f"{fail_bad.get('error')!r}"
    )
    assert fail_bad.get("cause") == (
        "An error occurred while executing the state 'FailBad' (entered at the event id #4). "
        "The JSONata expression '$states.input.missing.deep' specified for the field 'Cause' "
        "returned nothing (undefined)."
    ), f"unexpected cause for the undefined Fail.Cause expression: {fail_bad.get('cause')!r}"

    # --- Succeed: Output expression resolves to nothing -> States.QueryEvaluationError -----
    succeed_bad = _run_execution(ctx, sm_arn, {"case": "succeed-bad", "n": 10})
    assert succeed_bad["status"] == "FAILED", (
        f"an undefined Output expression must fail the execution even on a Succeed state; got "
        f"{succeed_bad['status']!r}"
    )
    assert succeed_bad.get("error") == _EVAL_ERROR, (
        f"an undefined expression result in a Succeed field must report {_EVAL_ERROR!r}, got "
        f"{succeed_bad.get('error')!r}"
    )
    assert succeed_bad.get("cause") == (
        "An error occurred while executing the state 'SucceedBad' (entered at the event id #4). "
        "The JSONata expression '$states.input.missing.deep' specified for the field "
        "'Output/doubled' returned nothing (undefined)."
    ), f"unexpected cause for the undefined Succeed.Output expression: {succeed_bad.get('cause')!r}"
    assert "output" not in succeed_bad, (
        f"a FAILED execution must carry no output, got {succeed_bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
