"""choice-null-execution-input-is-null-not-absent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-null-execution-input-is-null-not-absent"
GROUP = "choice_state"
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


def _run_execution(ctx, sm_arn, raw_input, *, timeout_s=60):
    """Start one execution with a raw JSON-text input, wait for a terminal status."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-choice-ex-"),
        input=raw_input,
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(0.5)
    raise AssertionError(
        f"execution for input {raw_input!r} never reached a terminal status within "
        f"{timeout_s}s; last describe was {desc!r}"
    )


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


_DEFINITION = {
    "StartAt": "Classify",
    "States": {
        "Classify": {
            "Type": "Choice",
            "Choices": [{"Variable": "$", "IsNull": True, "Next": "Null"}],
            "Default": "NotNull",
        },
        "Null": {"Type": "Pass", "Result": "null", "End": True},
        "NotNull": {"Type": "Pass", "Result": "not-null", "End": True},
    },
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An execution whose input is the JSON literal null is a PRESENT null document: a Choice
    testing `Variable: "$"` with `IsNull: true` takes that branch, not Default.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-choice-state.html
    """
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(ctx, _DEFINITION, role_arn)

    desc = _run_execution(ctx, sm_arn, "null")
    assert desc["status"] == "SUCCEEDED", (
        f"a literal JSON null execution input must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert _output(desc) == "null", (
        f"input 'null' must route to the IsNull branch; expected output 'null', got "
        f"{_output(desc)!r}"
    )

    # Control: a non-null document the same machine does not classify as null.
    control = _run_execution(ctx, sm_arn, json.dumps({"k": "v"}))
    assert control["status"] == "SUCCEEDED", (
        f"the control execution must succeed, got status={control.get('status')} "
        f"error={control.get('error')!r} cause={control.get('cause')!r}"
    )
    assert _output(control) == "not-null", (
        f"a non-null document must route to Default; expected 'not-null', got "
        f"{_output(control)!r} -- this is what attributes 'null' above to the literal null input, "
        f"not to a machine that always takes the Null branch"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
