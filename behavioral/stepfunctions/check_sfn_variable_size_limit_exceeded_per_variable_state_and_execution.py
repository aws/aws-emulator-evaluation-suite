"""sfn-variable-size-limit-exceeded-per-variable-state-and-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-variable-size-limit-exceeded-per-variable-state-and-execution"
GROUP = "variables"
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


def _pad(width: int, char: str = "x") -> str:
    """A JSONata expression producing a `width`-character string with no literal payload text."""
    return f"{{% $pad('', {width}, '{char}') %}}"


def _execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnvarlim-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-behav: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "sfn-variable-size-limit"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnvarlim-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="EXPRESS",
                tags=[{"key": "sim2real", "value": "sfn-variable-size-limit"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_sync(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    return sfn.start_sync_execution(stateMachineArn=sm_arn, input="{}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A variable's assigned data is capped at three independent scopes -- a single variable, one
    state's combined Assign, and the resident total across the execution -- each failing with its
    own exact States.DataLimitExceeded cause, while a value exactly at the cap still succeeds.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/workflow-variables.html
    """
    role_arn = _execution_role(ctx)

    # Per-variable: exactly at the 262,144-byte cap (a 262,142-character string, +2 for the
    # JSON quotes) succeeds; one byte of content more pushes the serialized size to 262,146 and
    # fails with the exact per-variable cause.
    ok_arn = _create_state_machine(ctx, {
        "QueryLanguage": "JSONata",
        "StartAt": "PassState",
        "States": {
            "PassState": {"Type": "Pass", "Assign": {"one": _pad(262142)}, "End": True},
        },
    }, role_arn)
    ok_resp = _run_sync(ctx, ok_arn)
    assert ok_resp["status"] == "SUCCEEDED", (
        f"a variable exactly at the 262144-byte cap must succeed, got {ok_resp['status']!r} "
        f"error={ok_resp.get('error')!r} cause={ok_resp.get('cause')!r}"
    )

    over_arn = _create_state_machine(ctx, {
        "QueryLanguage": "JSONata",
        "StartAt": "PassState",
        "States": {
            "PassState": {"Type": "Pass", "Assign": {"one": _pad(262144)}, "End": True},
        },
    }, role_arn)
    over_resp = _run_sync(ctx, over_arn)
    assert over_resp["status"] == "FAILED", f"expected FAILED, got {over_resp!r}"
    assert over_resp["error"] == "States.DataLimitExceeded", f"unexpected error: {over_resp!r}"
    assert over_resp["cause"] == (
        "Variable size limit exceeded. Variable 'one' in state 'PassState' was assigned 262146 bytes."
    ), f"unexpected cause: {over_resp['cause']!r}"

    # Per-state: two variables, each individually under the per-variable cap, whose combined
    # Assign exceeds the 256 KiB state-total cap.
    state_total_arn = _create_state_machine(ctx, {
        "QueryLanguage": "JSONata",
        "StartAt": "PassState",
        "States": {
            "PassState": {
                "Type": "Pass",
                "Assign": {"a": _pad(150000, "x"), "b": _pad(150000, "y")},
                "End": True,
            },
        },
    }, role_arn)
    state_total_resp = _run_sync(ctx, state_total_arn)
    assert state_total_resp["status"] == "FAILED", f"expected FAILED, got {state_total_resp!r}"
    assert state_total_resp["error"] == "States.DataLimitExceeded", (
        f"unexpected error: {state_total_resp!r}"
    )
    assert state_total_resp["cause"] == (
        "State total variable size limit exceeded. Variable 'b' in state 'PassState' was "
        "assigned 150002 bytes, which caused the size of variables assigned in the state to "
        "exceed its limit by 37860 bytes."
    ), f"unexpected cause: {state_total_resp['cause']!r}"

    # Per-execution: 40 distinct variables, each exactly at the per-variable cap, sum to exactly
    # the 10 MiB execution-total cap; a 41st distinct variable of any size pushes it over.
    exec_states = {}
    for i in range(1, 41):
        exec_states[f"S{i}"] = {
            "Type": "Pass",
            "Assign": {f"v{i}": _pad(262142)},
            "Next": f"S{i + 1}",
        }
    exec_states["S41"] = {"Type": "Pass", "Assign": {"v41": _pad(0)}, "End": True}
    exec_total_arn = _create_state_machine(
        ctx, {"QueryLanguage": "JSONata", "StartAt": "S1", "States": exec_states}, role_arn
    )
    exec_total_resp = _run_sync(ctx, exec_total_arn)
    assert exec_total_resp["status"] == "FAILED", f"expected FAILED, got {exec_total_resp!r}"
    assert exec_total_resp["error"] == "States.DataLimitExceeded", (
        f"unexpected error: {exec_total_resp!r}"
    )
    assert exec_total_resp["cause"] == (
        "Execution total variable size limit exceeded. State 'S41' assigned variables that "
        "exceed the total execution limit by 2 bytes."
    ), f"unexpected cause: {exec_total_resp['cause']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
