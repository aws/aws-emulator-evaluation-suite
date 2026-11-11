"""update-state-machine-invalid-role-arn-format-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-invalid-role-arn-format-rejected"
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
    """UpdateStateMachine with a roleArn that is not a well-formed ARN -> InvalidArn,
    and the state machine's roleArn is left exactly as it was before the attempt."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})

    name = ctx.unique_name("sim2real-behav-sm-updatearn-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name, definition=definition, roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))

    # --- Negative: UpdateStateMachine with a roleArn that is not well-formed -> InvalidArn.
    code, message = _error(
        lambda: sfn.update_state_machine(stateMachineArn=arn, roleArn="invalid-arn")
    )
    assert code == "InvalidArn", f"expected InvalidArn, got {code!r}"
    expected_message = "Invalid Role Arn: 'invalid-arn'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- Mutation proof: the rejected update left the state machine's roleArn untouched.
    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["roleArn"] == role_arn, (
        f"expected roleArn to remain {role_arn!r} after a rejected update, got {desc['roleArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
