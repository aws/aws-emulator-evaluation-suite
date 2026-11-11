"""wait-seconds-negative-literal-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-seconds-negative-literal-rejected"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_EXPECTED_MESSAGE = (
    "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Minimum value is 0 at "
    "/States/W/Seconds'"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine rejects a Wait state with a literal `Seconds: -10` as
    InvalidDefinition, naming the exact schema violation; a sibling definition whose Wait is
    `Seconds: 1` on the same role still succeeds."""
    sfn = ctx.client("stepfunctions")
    role_arn = _sfn_role(ctx)

    # --- Positive control: the same shape with a non-negative literal Seconds succeeds.
    valid_definition = {
        "StartAt": "W",
        "States": {
            "W": {"Type": "Wait", "Seconds": 1, "Next": "Done"},
            "Done": {"Type": "Pass", "End": True},
        },
    }
    valid_arn = _create_state_machine(ctx, role_arn, valid_definition)
    desc = sfn.describe_state_machine(stateMachineArn=valid_arn)
    assert desc["status"] == "ACTIVE", f"expected ACTIVE, got {desc['status']!r}"

    # --- Negative: a literal Seconds: -10 fails schema validation at CreateStateMachine.
    invalid_name = ctx.unique_name("sim2real-sfn-interp-sm-")
    invalid_definition = {
        "StartAt": "W",
        "States": {
            "W": {"Type": "Wait", "Seconds": -10, "Next": "Done"},
            "Done": {"Type": "Pass", "End": True},
        },
    }
    code, message = _refusal(lambda: sfn.create_state_machine(
        name=invalid_name, definition=json.dumps(invalid_definition), roleArn=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    ))
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code!r}"
    assert message == _EXPECTED_MESSAGE, f"expected message {_EXPECTED_MESSAGE!r}, got {message!r}"

    names = [sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert invalid_name not in names, (
        f"{invalid_name} must not exist after an InvalidDefinition rejection"
    )


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume. These definitions call no other service, so it needs no
    permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-interp-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn, definition) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the fresh
    role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-interp-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
