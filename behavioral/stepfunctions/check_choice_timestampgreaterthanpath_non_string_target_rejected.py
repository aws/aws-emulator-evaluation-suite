"""choice-timestampgreaterthanpath-non-string-target-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-timestampgreaterthanpath-non-string-target-rejected"
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
    name = ctx.unique_name("sim2real-choicetspath-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choicetspath: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choicetspath"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-choicetspath-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "choicetspath"}],
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
        name=ctx.unique_name("sim2real-choicetspath-ex-"),
        input=json.dumps(input_data),
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
        f"execution for input {input_data!r} never reached a terminal status within "
        f"{timeout_s}s; last describe was {desc!r}"
    )


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TimestampGreaterThanPath resolving to a number fails the execution with States.Runtime
    naming the offending path, while the same machine given a timestamp string matches the rule.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-choice-state.html
    """
    role_arn = _execution_role(ctx)
    definition = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$$.State.EnteredTime",
                        "TimestampGreaterThanPath": "$.threshold",
                        "Next": "After",
                    }
                ],
                "Default": "Fallback",
            },
            "After": {"Type": "Pass", "Result": "after", "End": True},
            "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # --- Positive control: the referenced path resolves to a real timestamp, well before
    # $$.State.EnteredTime (today), so the rule matches and the execution succeeds. ---
    ok = _run_execution(ctx, sm_arn, {"threshold": "2000-01-01T00:00:00Z"})
    assert ok["status"] == "SUCCEEDED", (
        f"a threshold resolving to a real past timestamp must succeed; got "
        f"status={ok.get('status')} error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert _output(ok) == "after", f"expected output 'after', got {_output(ok)!r}"

    # --- The subject: TimestampGreaterThanPath's own target resolves to a NUMBER, not a
    # timestamp string, which the comparator cannot evaluate at all. ---
    bad = _run_execution(ctx, sm_arn, {"threshold": 42})
    assert bad["status"] == "FAILED", (
        f"a TimestampGreaterThanPath target that resolves to a number must FAIL the execution, "
        f"got status={bad.get('status')} output={bad.get('output')!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} (cause={bad.get('cause')!r})"
    )
    assert bad.get("cause") == (
        "An error occurred while executing the state 'Route' (entered at the event id #2). "
        "Invalid value provided at path '$.threshold'"
    ), f"the cause must name the comparator path whose value is invalid; got {bad.get('cause')!r}"
    assert "output" not in bad or bad.get("output") is None, (
        f"a failed execution must not carry output, got {bad.get('output')!r}"
    )

    # The control case still works after the failure -- the state machine was not poisoned.
    again = _run_execution(ctx, sm_arn, {"threshold": "2000-01-01T00:00:00Z"})
    assert again["status"] == "SUCCEEDED" and _output(again) == "after", (
        f"the control case must still succeed after the failing execution, got "
        f"status={again.get('status')} output={_output(again)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
