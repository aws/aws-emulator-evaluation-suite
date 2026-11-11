"""map-non-array-input-fails-states-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-non-array-input-fails-states-runtime"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_RUNTIME_ERROR = "States.Runtime"
_RUNTIME_CAUSE = 'Reference path "$" must point to array.'


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
            "Comment": "an inline Map with no ItemsPath override, so the default '$' must point to an array",
            "StartAt": "MapState",
            "States": {
                "MapState": {
                    "Type": "Map",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "Echo",
                        "States": {"Echo": {"Type": "Pass", "End": True}},
                    },
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmapna-role-")
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
    name = ctx.unique_name("sim2real-behav-sfnmapna-")
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


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Map state whose default ItemsPath '$' resolves to a non-array input fails the
    execution with States.Runtime, naming the reference path that must point to an array."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: the whole input is itself an array -------------------------
    ok = sfn.start_sync_execution(
        stateMachineArn=sm_arn,
        input=json.dumps([{"n": 1}, {"n": 2}, {"n": 3}]),
    )
    assert ok["status"] == "SUCCEEDED", (
        "a Map whose default ItemsPath resolves to an array input must report SUCCEEDED — "
        f"without this control the failure assertions below cannot tell a working Map from "
        f"one that fails on everything; got {ok['status']!r} error={ok.get('error')!r} "
        f"cause={ok.get('cause')!r}"
    )
    ok_output = json.loads(ok["output"])
    assert ok_output == [{"n": 1}, {"n": 2}, {"n": 3}], (
        f"expected the array input echoed back unchanged, got {ok_output!r}"
    )

    # --- The subject: the whole input is a JSON object, not an array ------------------
    try:
        bad = sfn.start_sync_execution(
            stateMachineArn=sm_arn,
            input=json.dumps({"not": "an array"}),
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a Map-state failure inside a successful "
            f"response carrying status=FAILED; it raised {err.get('Code')!r} instead "
            f"({err.get('Message')!r})."
        ) from exc

    assert bad["status"] == "FAILED", (
        f"a Map whose '$' resolves to a non-array input must report status FAILED; "
        f"got {bad['status']!r}"
    )
    assert bad.get("error") == _RUNTIME_ERROR, (
        f"expected error {_RUNTIME_ERROR!r}, got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == _RUNTIME_CAUSE, (
        f"expected cause {_RUNTIME_CAUSE!r}, got {bad.get('cause')!r}"
    )
    assert "output" not in bad, (
        f"a FAILED synchronous Express execution has no output; it carried "
        f"output={bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
