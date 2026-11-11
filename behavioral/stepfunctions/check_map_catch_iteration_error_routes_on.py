"""map-catch-iteration-error-routes-on."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-catch-iteration-error-routes-on"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_FAIL_ERROR = "MapItemBoom"
_FAIL_CAUSE = "the second item in the array deliberately reaches the Fail state"


def _trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _definition(*, with_catch: bool) -> str:
    map_state = {
        "Type": "Map",
        "ItemsPath": "$.items",
        "MaxConcurrency": 1,
        "ItemProcessor": {
            "ProcessorConfig": {"Mode": "INLINE"},
            "StartAt": "RouteItem",
            "States": {
                "RouteItem": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.n", "NumericEquals": 1, "Next": "Boom"}
                    ],
                    "Default": "Ok",
                },
                "Ok": {
                    "Type": "Pass",
                    "Parameters": {"n.$": "$.n", "handled": True},
                    "End": True,
                },
                "Boom": {"Type": "Fail", "Error": _FAIL_ERROR, "Cause": _FAIL_CAUSE},
            },
        },
        "ResultPath": "$.mapResult",
    }
    map_state["Next"] = "Done"
    states = {
        "MapState": map_state,
        "Done": {"Type": "Pass", "Parameters": {"recovered": False}, "End": True},
    }
    if with_catch:
        map_state["Catch"] = [
            {"ErrorEquals": ["States.ALL"], "ResultPath": "$.err", "Next": "Recovered"}
        ]
        states["Recovered"] = {
            "Type": "Pass",
            "Parameters": {"recovered": True, "error.$": "$.err.Error"},
            "End": True,
        }
    return json.dumps({"StartAt": "MapState", "States": states})


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmapcatch-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """A STANDARD state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmapcatch-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _start_execution(ctx, sm_arn: str, input_data: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))[
        "executionArn"
    ]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, deadline_s: float = 90.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {deadline_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Catch on an inline Map catches an iteration's Fail error and routes the
    execution on to the catcher's Next state, instead of failing the execution."""
    role_arn = _create_sfn_role(ctx)
    sm_with_catch = _create_state_machine(ctx, role_arn, _definition(with_catch=True))
    sm_without_catch = _create_state_machine(ctx, role_arn, _definition(with_catch=False))

    payload = {"items": [{"n": 0}, {"n": 1}, {"n": 2}]}

    # --- The subject: the Map's own Catch catches the iteration's Fail error -----------
    caught_exec = _start_execution(ctx, sm_with_catch, payload)
    caught = _wait_terminal(ctx, caught_exec)
    assert caught["status"] == "SUCCEEDED", (
        "a Map with a Catch must still complete the execution successfully when an "
        f"iteration fails; got status={caught['status']!r} error={caught.get('error')!r} "
        f"cause={caught.get('cause')!r}"
    )
    caught_output = json.loads(caught["output"])
    assert caught_output == {"recovered": True, "error": _FAIL_ERROR}, (
        f"a caught Map iteration error must route to the Catch handler with the Fail "
        f"state's Error available at the Catch's ResultPath; got {caught_output!r}"
    )

    # --- Control: without a Catch, the same failing item fails the whole execution -----
    uncaught_exec = _start_execution(ctx, sm_without_catch, payload)
    uncaught = _wait_terminal(ctx, uncaught_exec)
    assert uncaught["status"] == "FAILED", (
        "without a Catch, a Map whose iteration reaches a Fail state must fail the whole "
        f"execution — without this control the Catch assertion above cannot tell a "
        f"working Catch from a Map that always succeeds regardless of its items; got "
        f"status={uncaught['status']!r}"
    )
    assert uncaught.get("error") == _FAIL_ERROR, (
        f"the uncaught execution must carry the inner Fail state's Error verbatim; "
        f"expected {_FAIL_ERROR!r}, got {uncaught.get('error')!r}"
    )

    # --- Positive control: all items take the Ok path on the Catch-bearing machine -----
    ok_exec = _start_execution(ctx, sm_with_catch, {"items": [{"n": 0}, {"n": 2}, {"n": 3}]})
    ok = _wait_terminal(ctx, ok_exec)
    assert ok["status"] == "SUCCEEDED", (
        f"a Map whose items all avoid the Fail branch must succeed; got {ok['status']!r} "
        f"error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    ok_output = json.loads(ok["output"])
    assert ok_output == {"recovered": False}, (
        f"when no item fails the Map must skip the Catch and reach Done (recovered: "
        f"False); got {ok_output!r} — a target that always routes to the Catch handler "
        f"would wrongly produce recovered: True here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
