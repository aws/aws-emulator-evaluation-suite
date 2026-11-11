"""deep-sfn-2-sfn-jsonata-state-error-caught-by-jsonpath-catch."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deep-sfn-2-sfn-jsonata-state-error-caught-by-jsonpath-catch"
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
    """A throwaway execution role: every state here is Parallel/Pass, no service call."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mql-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-mql: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "mql"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-mql-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "mql"}],
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
        name=ctx.unique_name("sim2real-mql-ex-"),
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


def _definition():
    """Top machine JSONPath (the default); the Parallel's own Catch is therefore JSONPath too,
    even though the Pass state it wraps is overridden to JSONata."""
    return {
        "StartAt": "Wrapper",
        "States": {
            "Wrapper": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "JsonataPass",
                        "States": {
                            "JsonataPass": {
                                "Type": "Pass",
                                "QueryLanguage": "JSONata",
                                "Output": {
                                    "v": (
                                        "{% $states.input.safe ? $states.input.n * 2 : "
                                        "$states.input.missing.deep %}"
                                    )
                                },
                                "End": True,
                            }
                        },
                    }
                ],
                "Catch": [
                    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.caught", "Next": "Check"},
                ],
                "ResultPath": "$.result",
                "Next": "Done",
            },
            "Check": {"Type": "Pass", "OutputPath": "$.caught", "End": True},
            "Done": {"Type": "Pass", "OutputPath": "$.result", "End": True},
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
    """A Parallel's own JSONPath Catch, with a ResultPath, catches States.QueryEvaluationError
    raised by an inner branch state overridden to JSONata, carrying the default
    Error/Cause shape; the success path still reaches the Parallel's own ResultPath unchanged."""
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(ctx, _definition(), role_arn)

    # --- Positive control: the JSONata branch's expression evaluates fine ------------------
    ok = _run_execution(ctx, sm_arn, {"safe": True, "n": 10})
    assert ok["status"] == "SUCCEEDED", (
        f"the positive control must succeed; got {ok['status']!r} error={ok.get('error')!r} "
        f"cause={ok.get('cause')!r}"
    )
    assert _output(ok) == [{"v": 20}], (
        f"the Parallel's own ResultPath must carry the branch's JSONata output array unchanged, "
        f"got {_output(ok)!r}"
    )

    # --- The subject: the JSONata branch's expression resolves to nothing ------------------
    bad = _run_execution(ctx, sm_arn, {"safe": False, "n": 10})
    assert bad["status"] == "SUCCEEDED", (
        f"the Parallel's own JSONPath Catch must turn the inner JSONata failure into a caught "
        f"success; got {bad['status']!r} error={bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    out = _output(bad)
    assert out is not None and out.get("Error") == "States.QueryEvaluationError", (
        f"a JSONPath Catch's default ResultPath payload must carry Error="
        f"'States.QueryEvaluationError'; got {out!r}"
    )
    assert out.get("Cause") == (
        "An error occurred while executing the state 'JsonataPass' (entered at the event id "
        "#4). The JSONata expression '$states.input.safe ? $states.input.n * 2 : "
        "$states.input.missing.deep' specified for the field 'Output/v' returned nothing "
        "(undefined)."
    ), f"unexpected Cause in the JSONPath Catch's output: {out.get('Cause')!r}"
    assert set(out) == {"Error", "Cause"}, (
        f"the default JSONPath Catch payload must be exactly Error/Cause, got keys {sorted(out)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
