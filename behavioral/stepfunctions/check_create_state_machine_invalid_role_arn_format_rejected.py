"""create-state-machine-invalid-role-arn-format-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-invalid-role-arn-format-rejected"
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
    """CreateStateMachine with a roleArn that is not a well-formed ARN -> InvalidArn
    naming the malformed value; a well-formed role ARN still creates the state machine."""
    sfn = ctx.client("stepfunctions")
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})

    # --- Negative: a roleArn that is not even a well-formed ARN -> InvalidArn.
    bad_name = ctx.unique_name("sim2real-behav-sm-badarn-")
    code, message = _error(
        lambda: sfn.create_state_machine(
            name=bad_name, definition=definition, roleArn="invalid-arn",
        )
    )
    assert code == "InvalidArn", f"expected InvalidArn, got {code!r}"
    expected_message = "Invalid Role Arn: 'invalid-arn'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- Positive control: a well-formed, existing role ARN still creates the state machine.
    role_arn = _create_sfn_role(ctx)
    good_name = ctx.unique_name("sim2real-behav-sm-goodarn-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=good_name, definition=definition, roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {desc['roleArn']!r}"

    # The rejected create left nothing behind under its name.
    bad_arn = f"{arn.rsplit(':', 1)[0]}:{bad_name}"
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_arn))
    assert code == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist for {bad_arn!r} after an InvalidArn rejection, got {code!r}"
    )
    expected_message = f"State Machine Does Not Exist: '{bad_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
