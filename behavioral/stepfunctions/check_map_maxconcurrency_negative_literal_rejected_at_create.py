"""map-maxconcurrency-negative-literal-rejected-at-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-maxconcurrency-negative-literal-rejected-at-create"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_MAP_STATE = "M"

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_sfn_role(ctx) -> str:
    """A Step Functions execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmcneg-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _definition(*, mode: str, max_concurrency) -> dict:
    processor_config = {"Mode": mode}
    if mode == "DISTRIBUTED":
        processor_config["ExecutionType"] = "STANDARD"
    return {
        "StartAt": _MAP_STATE,
        "States": {
            _MAP_STATE: {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": max_concurrency,
                "ItemProcessor": {
                    "ProcessorConfig": processor_config,
                    "StartAt": "Hold",
                    "States": {"Hold": {"Type": "Wait", "Seconds": 2, "End": True}},
                },
                "End": True,
            }
        },
    }


def _create_state_machine_error(ctx, role_arn: str, definition: dict):
    """Attempt CreateStateMachine and return the (code, message) it raised, retrying only
    the AccessDenied window while the role's trust grant propagates. A success raises --
    the caller is asserting this definition is refused."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmcneg-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return code, exc.response["Error"]["Message"]
        # Unexpected success: clean it up before failing loudly.
        arn = resp["stateMachineArn"]
        sfn.delete_state_machine(stateMachineArn=arn)
        raise AssertionError(
            f"expected CreateStateMachine to reject MaxConcurrency={definition['States'][_MAP_STATE]['MaxConcurrency']!r}, "
            f"but it succeeded and returned {arn!r}"
        )


def _create_state_machine_ok(ctx, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmcneg-ok-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


_EXPECTED_MESSAGE = (
    "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Minimum value is 0 at "
    f"/States/{_MAP_STATE}/MaxConcurrency'"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine rejects a literal negative Map MaxConcurrency with
    InvalidDefinition naming the schema violation, identically for an INLINE and a
    DISTRIBUTED ItemProcessor."""
    role_arn = _create_sfn_role(ctx)

    ok_arn = _create_state_machine_ok(ctx, role_arn, _definition(mode="INLINE", max_concurrency=2))
    assert ok_arn, "positive control: a valid MaxConcurrency must be accepted"

    for mode in ("INLINE", "DISTRIBUTED"):
        code, message = _create_state_machine_error(
            ctx, role_arn, _definition(mode=mode, max_concurrency=-1)
        )
        assert code == "InvalidDefinition", f"{mode}: expected InvalidDefinition, got {code!r}"
        assert message == _EXPECTED_MESSAGE, (
            f"{mode}: unexpected InvalidDefinition message: {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
