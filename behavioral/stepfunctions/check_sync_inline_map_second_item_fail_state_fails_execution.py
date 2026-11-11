"""sync-inline-map-second-item-fail-state-fails-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-inline-map-second-item-fail-state-fails-execution"
GROUP = "express_workflows"
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


def _definition() -> str:
    return json.dumps(
        {
            "Comment": "an inline Map whose second item's ItemProcessor reaches a Fail state",
            "StartAt": "MapState",
            "States": {
                "MapState": {
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
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmap-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmap-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_definition(),
                roleArn=role_arn,
                type="EXPRESS",
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
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A synchronous Express execution of an inline Map whose second item's ItemProcessor
    reaches a Fail state ends FAILED, carrying that Fail state's Error and Cause verbatim."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: all three items take the Ok path --------------------------
    ok = sfn.start_sync_execution(
        stateMachineArn=sm_arn,
        input=json.dumps({"items": [{"n": 0}, {"n": 2}, {"n": 3}]}),
    )
    assert ok["status"] == "SUCCEEDED", (
        "a Map whose items all avoid the Fail branch must report SUCCEEDED — without this "
        f"control the failure assertions below cannot tell a working Map from one that fails "
        f"on everything; got {ok['status']!r} error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    ok_output = json.loads(ok["output"])
    assert ok_output == [
        {"n": 0, "handled": True},
        {"n": 2, "handled": True},
        {"n": 3, "handled": True},
    ], f"expected every item mapped through Ok, got {ok_output!r}"

    # --- The subject: the second item (n=1) reaches the Fail state ---------------------
    try:
        boom = sfn.start_sync_execution(
            stateMachineArn=sm_arn,
            input=json.dumps({"items": [{"n": 0}, {"n": 1}, {"n": 2}]}),
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a Map-iteration failure inside a successful "
            f"response carrying status=FAILED; it raised {err.get('Code')!r} instead "
            f"({err.get('Message')!r})."
        ) from exc

    assert boom["status"] == "FAILED", (
        f"the Map with a failing second item must report status FAILED; got {boom['status']!r}"
    )
    assert boom.get("error") == _FAIL_ERROR, (
        f"the sync response must carry the inner Fail state's Error verbatim; expected "
        f"{_FAIL_ERROR!r}, got {boom.get('error')!r}"
    )
    assert boom.get("cause") == _FAIL_CAUSE, (
        f"the sync response must carry the inner Fail state's Cause verbatim; expected "
        f"{_FAIL_CAUSE!r}, got {boom.get('cause')!r}"
    )
    assert "output" not in boom, (
        f"a FAILED synchronous Express execution has no output, so no partially-mapped "
        f"array may leak through; it carried output={boom.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
