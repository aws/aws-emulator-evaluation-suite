"""choice-jsonata-rule-assign-scoped-inside-map-caught-by-catch."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "choice-jsonata-rule-assign-scoped-inside-map-caught-by-catch"
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
    """A throwaway execution role: every state here is Map/Choice/Pass, no service call."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cmc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-cmc: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "cmc"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-cmc-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "cmc"}],
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
        name=ctx.unique_name("sim2real-cmc-ex-"),
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


def _definition():
    return {
        "QueryLanguage": "JSONata",
        "StartAt": "MapState",
        "States": {
            "MapState": {
                "Type": "Map",
                "Items": "{% $states.input.items %}",
                "MaxConcurrency": 1,
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Route",
                    "States": {
                        "Route": {
                            "Type": "Choice",
                            "Choices": [
                                {
                                    "Condition": "{% $states.input.n > 0 %}",
                                    "Next": "Positive",
                                    "Assign": {
                                        "tag": "{% 'positive-' & $string($states.input.n) %}"
                                    },
                                },
                            ],
                            "Default": "NonPositive",
                        },
                        "Positive": {
                            "Type": "Pass",
                            "Output": {"branch": "positive", "tag": "{% $tag %}"},
                            "End": True,
                        },
                        "NonPositive": {
                            "Type": "Pass",
                            "Output": {"branch": "non-positive", "tag": "{% $tag %}"},
                            "End": True,
                        },
                    },
                },
                "Catch": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "Output": {
                            "caught": True,
                            "error": "{% $states.errorOutput.Error %}",
                            "cause": "{% $states.errorOutput.Cause %}",
                        },
                        "Next": "Caught",
                    },
                ],
                "Output": {"caught": False, "items": "{% $states.result %}"},
                "Next": "Done",
            },
            "Caught": {"Type": "Pass", "End": True},
            "Done": {"Type": "Pass", "End": True},
        },
    }


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A JSONata Choice nested in a Map's ItemProcessor still scopes its per-rule Assign to the
    matched rule and the current item alone; a non-matching item that never assigned the variable
    raises States.QueryEvaluationError, which the enclosing Map's Catch catches."""
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(ctx, _definition(), role_arn)

    # --- Positive control: every item matches the rule, Assign scoped per item -------------
    control = _run_execution(ctx, sm_arn, {"items": [{"n": 1}, {"n": 2}]})
    assert control["status"] == "SUCCEEDED", (
        f"all-positive items must succeed; got {control['status']!r} "
        f"error={control.get('error')!r} cause={control.get('cause')!r}"
    )
    assert _output(control) == {
        "caught": False,
        "items": [
            {"branch": "positive", "tag": "positive-1"},
            {"branch": "positive", "tag": "positive-2"},
        ],
    }, (
        f"each item's own Assign must produce its own tag, not a prior iteration's; got "
        f"{_output(control)!r}"
    )

    # --- The subject: the second item takes Default, never Assign-ing $tag -----------------
    mixed = _run_execution(ctx, sm_arn, {"items": [{"n": 1}, {"n": -5}]})
    assert mixed["status"] == "SUCCEEDED", (
        f"the Map's own Catch must turn the inner failure into a caught success; got "
        f"{mixed['status']!r} error={mixed.get('error')!r} cause={mixed.get('cause')!r}"
    )
    out = _output(mixed)
    assert out is not None and out.get("caught") is True, (
        f"the Map's Catch must have run, got output {out!r}"
    )
    assert out.get("error") == _EVAL_ERROR, (
        f"the error the Map caught must be {_EVAL_ERROR!r} (the unassigned $tag), got "
        f"{out.get('error')!r}"
    )
    assert out.get("cause") == (
        "An error occurred while executing the state 'NonPositive' (entered at the event id "
        "#13). The JSONata expression '$tag' specified for the field 'Output/tag' returned "
        "nothing (undefined)."
    ), f"unexpected caught cause: {out.get('cause')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
