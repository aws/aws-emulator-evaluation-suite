"""map-invalid-input-path-fails-states-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-invalid-input-path-fails-states-runtime"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_INPUT_PATH = "$.invalid"


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
            "Comment": "a Map state whose InputPath names a field absent from its own input",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.mode", "StringEquals": "bad", "Next": "BadMap"}
                    ],
                    "Default": "GoodMap",
                },
                "GoodMap": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "Echo",
                        "States": {"Echo": {"Type": "Pass", "End": True}},
                    },
                    "End": True,
                },
                "BadMap": {
                    "Type": "Map",
                    "InputPath": _INPUT_PATH,
                    "ItemsPath": "$.items",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "EchoBad",
                        "States": {"EchoBad": {"Type": "Pass", "End": True}},
                    },
                    "End": True,
                },
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmapinput-role-")
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
    name = ctx.unique_name("sim2real-behav-sfnmapinput-")
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Map state whose InputPath names a field absent from its own input ends FAILED
    with States.Runtime, carrying the Map-specific cause form naming the missing path."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: the Default path's Map has no InputPath -----------------
    ok = sfn.start_sync_execution(
        stateMachineArn=sm_arn, input=json.dumps({"mode": "ok", "items": [1, 2, 3]})
    )
    assert ok["status"] == "SUCCEEDED", (
        "the mode=ok path (no InputPath on the Map) must report SUCCEEDED — without this "
        f"control the failure assertions below cannot tell a working sync endpoint from "
        f"one that answers FAILED to everything; got {ok['status']!r} "
        f"error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"]) == [1, 2, 3], (
        f"expected the Map to pass every item through Echo unchanged, got {ok['output']!r}"
    )

    # --- The subject: InputPath names a field the Map's own input lacks ----------------
    try:
        bad = sfn.start_sync_execution(
            stateMachineArn=sm_arn, input=json.dumps({"mode": "bad", "items": [1, 2, 3]})
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a Map InputPath runtime failure inside a "
            f"successful response carrying status=FAILED; it raised {err.get('Code')!r} "
            f"instead ({err.get('Message')!r})."
        ) from exc

    assert bad["status"] == "FAILED", (
        f"a Map state whose InputPath selects an absent field must report status FAILED; "
        f"got {bad['status']!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"the sync response must carry error 'States.Runtime'; got {bad.get('error')!r}"
    )
    expected_cause = (
        "An error occurred while executing the state 'BadMap' (entered at the event "
        f"id #4). Invalid path '{_INPUT_PATH}' : No results for path: $['invalid']"
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert "output" not in bad, (
        f"a FAILED synchronous Express execution has no output; it carried "
        f"output={bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
