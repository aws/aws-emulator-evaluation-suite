"""delete-version-referenced-by-alias-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-version-referenced-by-alias-conflict"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _not_exist_message(version_arn):
    return f"State Machine Version Does Not Exist: '{version_arn}'"


def _conflict_message(alias_name):
    return (
        "Version to be deleted must not be referenced by an alias. "
        f"Current list of aliases referencing this version: [{alias_name}]"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStateMachineVersion on a version still referenced by an alias -> ConflictException,
    the version survives untouched, and once the alias no longer references it the IDENTICAL
    delete call succeeds."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))

    # Positive control: an unreferenced version on this SAME state machine deletes cleanly, so
    # the conflict below cannot be "every DeleteStateMachineVersion call fails". Done and settled
    # BEFORE v1 is published, so it cannot perturb the alias-creation timing on v1 below.
    vpc_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    sfn.delete_state_machine_version(stateMachineVersionArn=vpc_arn)
    code_vpc, message_vpc = _error(lambda: sfn.describe_state_machine(stateMachineArn=vpc_arn))
    assert code_vpc == "StateMachineDoesNotExist", f"positive control: version should be gone after delete, got {code_vpc}"
    assert message_vpc == _not_exist_message(vpc_arn), (
        f"expected message {_not_exist_message(vpc_arn)!r}, got {message_vpc!r}"
    )

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    alias_name = ctx.unique_name("sim2real-behav-alias-")
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )
    alias_arn = f"{arn}:{alias_name}"
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))

    code, message = _error(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn))
    assert code == "ConflictException", f"expected ConflictException deleting an alias-referenced version, got {code}"
    assert message == _conflict_message(alias_name), (
        f"expected message {_conflict_message(alias_name)!r}, got {message!r}"
    )

    # Effect absent: the rejected delete must not have touched the version.
    desc = sfn.describe_state_machine(stateMachineArn=v1_arn)
    assert desc["stateMachineArn"] == v1_arn

    # Restore: remove the reference, then the IDENTICAL delete call must succeed.
    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)
    sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn)
    final_code, final_message = _error(lambda: sfn.describe_state_machine(stateMachineArn=v1_arn))
    assert final_code == "StateMachineDoesNotExist", (
        f"expected v1 gone once the alias reference is removed, got {final_code}"
    )
    assert final_message == _not_exist_message(v1_arn), (
        f"expected message {_not_exist_message(v1_arn)!r}, got {final_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
