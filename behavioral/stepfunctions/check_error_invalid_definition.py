"""error-invalid-definition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-definition"
GROUP = 'errors'
SERVICES = ['stepfunctions']

def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine with invalid ASL -> InvalidDefinition; a well-formed
    definition on the same role still succeeds, and the rejected attempt never
    shows up in the account's state machine list."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # --- Positive control: a well-formed definition succeeds.
    valid_name = ctx.unique_name("sim2real-behav-sm-valid-")
    valid_definition = json.dumps(
        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    valid_arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=valid_name, definition=valid_definition, roleArn=role_arn
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=valid_arn))
    desc = sfn.describe_state_machine(stateMachineArn=valid_arn)
    assert desc["status"] == "ACTIVE", f"expected ACTIVE, got {desc['status']!r}"

    # --- Negative: syntactically-valid JSON that is not valid ASL -> InvalidDefinition.
    invalid_name = ctx.unique_name("sim2real-behav-sm-invalid-")
    code, message = _refusal(
        lambda: sfn.create_state_machine(
            name=invalid_name,
            definition='{"invalid": "not valid ASL"}',
            roleArn=role_arn,
        )
    )
    assert code == "InvalidDefinition", f"Expected InvalidDefinition, got {code!r}"
    expected_message = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: These fields are required: "
        "[States, StartAt] at /, SCHEMA_VALIDATION_FAILED: Field 'invalid' is not supported at /'"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    names = [
        sm["name"]
        for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])
    ]
    assert invalid_name not in names, (
        f"{invalid_name} should not exist after an InvalidDefinition rejection"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
