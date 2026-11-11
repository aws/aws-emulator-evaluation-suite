"""cross-account-alias-version-and-list-ops-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-account-alias-version-and-list-ops-access-denied"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]

_PASS_DEFINITION = json.dumps(
    {"Comment": "sim2real cross-account", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineAlias, a version read and List* calls on an ARN naming a state machine
    in another account are all AccessDeniedException with the exact IAM message, while the same
    four calls on this account's own state machine, alias and version all succeed.
    """
    sfn = ctx.client("stepfunctions")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)
    v1 = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1), "ResourceNotFound"))
    alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-behav-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": v1, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn), "ResourceNotFound"))

    # AWS's own documentation placeholder account id; the denial is evaluated before any resource
    # lookup, so it need not exist for the service to refuse it.
    foreign_account = "111122223333"
    foreign_sm_arn = sm_arn.replace(f":{ctx.account}:", f":{foreign_account}:")
    foreign_alias_arn = alias_arn.replace(f":{ctx.account}:", f":{foreign_account}:")
    foreign_version_arn = v1.replace(f":{ctx.account}:", f":{foreign_account}:")

    expected = {"Code": "AccessDeniedException", "Message": f"User: {caller_arn} is not authorized to access this resource"}

    err = _error(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=foreign_alias_arn))
    assert err == expected, f"DescribeStateMachineAlias on a foreign-account alias ARN: expected {expected!r}, got {err!r}"

    err = _error(lambda: sfn.describe_state_machine(stateMachineArn=foreign_version_arn))
    assert err == expected, f"a version read (DescribeStateMachine) on a foreign-account version ARN: expected {expected!r}, got {err!r}"

    err = _error(lambda: sfn.list_state_machine_aliases(stateMachineArn=foreign_sm_arn))
    assert err == expected, f"ListStateMachineAliases on a foreign-account state machine ARN: expected {expected!r}, got {err!r}"

    err = _error(lambda: sfn.list_state_machine_versions(stateMachineArn=foreign_sm_arn))
    assert err == expected, f"ListStateMachineVersions on a foreign-account state machine ARN: expected {expected!r}, got {err!r}"

    # Positive control: the identical four calls against this account's own resources succeed.
    own_alias_desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert own_alias_desc["stateMachineAliasArn"] == alias_arn, "positive control: describe alias must succeed on our own alias"

    own_version_desc = sfn.describe_state_machine(stateMachineArn=v1)
    assert own_version_desc["stateMachineArn"] == v1, "positive control: describing our own version must succeed"

    own_aliases = sfn.list_state_machine_aliases(stateMachineArn=sm_arn)["stateMachineAliases"]
    assert [a["stateMachineAliasArn"] for a in own_aliases] == [alias_arn], (
        f"positive control: listing our own aliases must succeed and show {alias_arn!r}, got {own_aliases!r}"
    )

    own_versions = sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"]
    assert [v["stateMachineVersionArn"] for v in own_versions] == [v1], (
        f"positive control: listing our own versions must succeed and show {v1!r}, got {own_versions!r}"
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


def _error(fn) -> dict:
    """The AWS error `fn` raises, as {"Code", "Message"}; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role's trust propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=_PASS_DEFINITION, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
