"""error-conflict-delete-state-machine-version-in-use."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-conflict-delete-state-machine-version-in-use"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStateMachineVersion must refuse to delete a version that is still referenced by an
    alias's routingConfiguration, returning ConflictException -- deleting it anyway would leave
    the alias pointing at a version that no longer exists."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    sm_name = ctx.unique_name("sim2real-behav-sm-verinuse-")
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    sm_arn = _create_state_machine(sfn, sm_name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))

    code, message = _refusal(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        "Version to be deleted must not be referenced by an alias. "
        f"Current list of aliases referencing this version: [{alias_name}]"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # The rejected delete must have no effect: the version is still there, independently of the
    # delete call's own (error) response.
    still_there = sfn.describe_state_machine(stateMachineArn=version_arn)
    assert still_there["stateMachineArn"] == version_arn, still_there

    # Once the alias is removed, deleting the (now-unreferenced) version must succeed.
    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)
    sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)

    # The delete must actually take effect: an independent read at the destination sees the
    # version gone.
    gone_code, gone_message = _refusal(lambda: sfn.describe_state_machine(stateMachineArn=version_arn))
    assert gone_code == "StateMachineDoesNotExist", f"version still describable after delete: {gone_code!r}"
    expected_gone_message = f"State Machine Version Does Not Exist: '{version_arn}'"
    assert gone_message == expected_gone_message, (
        f"expected message {expected_gone_message!r}, got {gone_message!r}"
    )

    # DeleteStateMachineVersion is idempotent for an already-deleted version (no not-found error
    # is modelled for it) -- confirmed on real AWS: a redelete must not raise.
    sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _create_state_machine(sfn, name, definition, role_arn):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
