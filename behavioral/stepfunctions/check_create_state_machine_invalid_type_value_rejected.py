"""create-state-machine-invalid-type-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-invalid-type-value-rejected"
GROUP = "errors"
SERVICES = ["stepfunctions"]


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


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine with a type value outside STANDARD/EXPRESS -> ValidationException
    naming the enum; a valid type still creates the state machine."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})

    # --- Negative: a type value outside the StateMachineType enum -> ValidationException.
    bad_name = ctx.unique_name("sim2real-behav-sm-badtype-")
    code, message = _error(
        lambda: sfn.create_state_machine(
            name=bad_name, definition=definition, roleArn=role_arn, type="BOGUS",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'BOGUS' at 'type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [EXPRESS, STANDARD]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- Positive control: an explicit, valid enum value still creates the state machine.
    good_name = ctx.unique_name("sim2real-behav-sm-goodtype-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=good_name, definition=definition, roleArn=role_arn, type="EXPRESS",
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["type"] == "EXPRESS", f"expected type EXPRESS, got {desc['type']!r}"

    names = [
        sm["name"]
        for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])
    ]
    assert bad_name not in names, (
        f"{bad_name} should not exist after a ValidationException rejection"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
