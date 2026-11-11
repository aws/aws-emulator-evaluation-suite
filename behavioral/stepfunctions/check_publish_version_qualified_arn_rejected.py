"""publish-version-qualified-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-version-qualified-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishStateMachineVersion on a version- or alias-qualified ARN is rejected as
    InvalidArn naming the qualifier, while the same call on the unqualified ARN succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)))

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)))

    version_code, version_message = _error(
        lambda: sfn.publish_state_machine_version(stateMachineArn=version_arn)
    )
    assert version_code == "InvalidArn", f"expected InvalidArn on a version-qualified ARN, got {version_code!r}"
    expected_version_message = f"State machine ARN must not have a qualifier suffix: {version_arn}"
    assert version_message == expected_version_message, (
        f"expected message {expected_version_message!r}, got {version_message!r}"
    )

    alias_code, alias_message = _error(
        lambda: sfn.publish_state_machine_version(stateMachineArn=alias_arn)
    )
    assert alias_code == "InvalidArn", f"expected InvalidArn on an alias-qualified ARN, got {alias_code!r}"
    expected_alias_message = f"State machine ARN must not have a qualifier suffix: {alias_arn}"
    assert alias_message == expected_alias_message, (
        f"expected message {expected_alias_message!r}, got {alias_message!r}"
    )

    # Positive control: the unqualified ARN is unaffected by the two rejections above. The
    # revision is unchanged since the first publish, so this is the documented idempotent
    # case and returns that same version rather than minting a new one.
    control = sfn.publish_state_machine_version(stateMachineArn=sm_arn)
    assert control["stateMachineVersionArn"] == version_arn, (
        f"expected the unqualified ARN to still publish the current revision as {version_arn!r}, "
        f"got {control['stateMachineVersionArn']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


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


def _swallow_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "StateMachineDoesNotExist"):
            raise


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=_PASS_DEFINITION, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"could not create state machine after role propagation wait: {last_err}"
        )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
