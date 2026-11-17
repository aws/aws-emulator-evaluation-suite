"""describe-state-machine-alias-invalid-arn-and-never-created-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-alias-invalid-arn-and-never-created-rejected"
GROUP = "update_versioning"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_PASS_DEFINITION = json.dumps(
    {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_PASS_DEFINITION, roleArn=role_arn
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises too, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineAlias rejects a malformed alias ARN with InvalidArn and a well-formed
    alias ARN that was never created with ResourceNotFound, each with its exact message.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    # Positive control: a real alias on this state machine describes successfully.
    alias_name = ctx.unique_name("sim2real-behav-alias-")
    routing = [{"stateMachineVersionArn": v1_arn, "weight": 100}]
    alias_arn = sfn.create_state_machine_alias(name=alias_name, routingConfiguration=routing)[
        "stateMachineAliasArn"
    ]
    control = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert control["name"] == alias_name, f"expected name {alias_name!r}, got {control['name']!r}"

    arn_code, arn_message = _error(
        lambda: sfn.describe_state_machine_alias(stateMachineAliasArn="not-an-arn")
    )
    assert arn_code == "InvalidArn", f"expected InvalidArn, got {arn_code!r}"
    expected_arn_message = "Invalid Arn: 'Invalid ARN prefix: not-an-arn'"
    assert arn_message == expected_arn_message, (
        f"expected message {expected_arn_message!r}, got {arn_message!r}"
    )

    never_created_arn = f"{sm_arn}:{ctx.unique_name('sim2real-behav-alias-never-')}"
    not_found_code, not_found_message = _error(
        lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=never_created_arn)
    )
    assert not_found_code == "ResourceNotFound", f"expected ResourceNotFound, got {not_found_code!r}"
    expected_not_found_message = f"Resource not found: '{never_created_arn}'"
    assert not_found_message == expected_not_found_message, (
        f"expected message {expected_not_found_message!r}, got {not_found_message!r}"
    )

    # The identical call against the real alias still succeeds after the two refusals.
    again = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert again["name"] == alias_name, (
        f"expected name {alias_name!r} after the rejected calls, got {again['name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
