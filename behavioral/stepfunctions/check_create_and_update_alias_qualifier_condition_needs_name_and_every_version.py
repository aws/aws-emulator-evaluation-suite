"""create-and-update-alias-qualifier-condition-needs-name-and-every-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-and-update-alias-qualifier-condition-needs-name-and-every-version"
GROUP = "permission-boundary"
SERVICES = ["stepfunctions"]

_PASS_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})
_PASS2_DEFINITION = json.dumps(
    {"StartAt": "P", "States": {"P": {"Type": "Pass", "Comment": "v2", "End": True}}}
)
_IAM_RETRY_DEADLINE_S = 90.0
_ACTIONS = ["states:CreateStateMachineAlias", "states:UpdateStateMachineAlias"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A states:StateMachineQualifier condition authorizing CreateStateMachineAlias/
    UpdateStateMachineAlias must list BOTH the alias name being written AND every version in its
    routingConfiguration: either missing is denied, and only granting both lets the call through."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sfn = ctx.client("stepfunctions")
    account = ctx.account

    exec_role_arn = _execution_role(ctx, iam)
    sm_arn = _create_state_machine(ctx, sfn, exec_role_arn, _PASS_DEFINITION)
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    v1_qualifier = v1_arn.rsplit(":", 1)[1]
    v2_arn = _publish_v2(sfn, sm_arn, exec_role_arn)
    v2_qualifier = v2_arn.rsplit(":", 1)[1]
    assert v2_qualifier != v1_qualifier, (
        f"publishing a changed definition must mint a new version; got the same qualifier "
        f"{v2_qualifier!r}"
    )
    alias_name = ctx.unique_name("sim2real-sfnalias-")[:80]

    # --- CreateStateMachineAlias: alias name allowed, but the routed version v1 is NOT ---
    name_only_arn, name_only_sfn, name_only_assumed = _caller(
        ctx, iam, sts, account, resource=sm_arn, allowed_qualifiers=[alias_name],
    )
    code, message = _error(lambda: name_only_sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]))
    assert code == "AccessDeniedException", (
        f"CreateStateMachineAlias must be denied when only the alias name, not the routed "
        f"version, is in the allowed qualifier set; got {code!r}"
    )
    assert message == (
        f"User: {name_only_assumed} is not authorized to perform: states:CreateStateMachineAlias "
        f"on resource: {sm_arn} because no identity-based policy allows the "
        f"states:CreateStateMachineAlias action"
    ), f"unexpected AccessDeniedException message: {message!r}"

    # --- Granting the name AND the routed version lets CreateStateMachineAlias through ---
    _, name_and_v1_sfn, name_and_v1_assumed = _caller(
        ctx, iam, sts, account, resource=sm_arn, allowed_qualifiers=[alias_name, v1_qualifier],
    )
    alias_arn = _retry_iam_propagation(lambda: name_and_v1_sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}],
    ))["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))
    created = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert created["routingConfiguration"] == [{"stateMachineVersionArn": v1_arn, "weight": 100}], (
        f"the alias must route to v1 as created; got {created.get('routingConfiguration')!r}"
    )

    # --- UpdateStateMachineAlias: the SAME role, whose allowed set still lacks v2, is denied
    # when repointing to v2, even though the alias name itself is still allowed.
    code, message = _error(lambda: name_and_v1_sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}]))
    assert code == "AccessDeniedException", (
        f"UpdateStateMachineAlias must be denied when the NEW routed version is outside the "
        f"allowed qualifier set; got {code!r}"
    )
    assert message == (
        f"User: {name_and_v1_assumed} is not authorized to perform: "
        f"states:UpdateStateMachineAlias on resource: {sm_arn} because no identity-based policy "
        f"allows the states:UpdateStateMachineAlias action"
    ), f"unexpected AccessDeniedException message: {message!r}"
    unchanged = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert unchanged["routingConfiguration"] == [{"stateMachineVersionArn": v1_arn, "weight": 100}], (
        f"a denied update must leave the alias routed exactly as before; got "
        f"{unchanged.get('routingConfiguration')!r}"
    )

    # --- Granting the name AND the new version lets UpdateStateMachineAlias through ---
    _, name_and_v2_sfn, _ = _caller(
        ctx, iam, sts, account, resource=sm_arn, allowed_qualifiers=[alias_name, v2_qualifier],
    )
    _retry_iam_propagation(lambda: name_and_v2_sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}]))
    updated = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert updated["routingConfiguration"] == [{"stateMachineVersionArn": v2_arn, "weight": 100}], (
        f"once both the name and the new version are allowed, the update must take effect; got "
        f"{updated.get('routingConfiguration')!r}"
    )


def _execution_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-sfnalias-exrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, sfn, role_arn: str, definition: str, timeout_s: float = 90.0) -> str:
    name = ctx.unique_name("sim2real-sfnalias-sm-")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    else:
        raise AssertionError(f"CreateStateMachine still AccessDenied after {timeout_s}s: {last}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _publish_v2(sfn, sm_arn: str, role_arn: str) -> str:
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_PASS2_DEFINITION, roleArn=role_arn)
    return sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]


def _caller(ctx, iam, sts, account, *, resource, allowed_qualifiers):
    """A fresh role, trusted by this account's root, scoped to ``_ACTIONS`` on ``resource`` by
    the given allowed StateMachineQualifier values -- a new role per permission level, never a
    rewritten one, so no test depends on how fast an in-place policy edit propagates."""
    name = ctx.unique_name("sim2real-sfnalias-caller-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                            "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = "sim2real-sfnalias-caller"
    iam.put_role_policy(
        RoleName=name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": _ACTIONS, "Resource": resource,
                "Condition": {"ForAllValues:StringEquals":
                              {"states:StateMachineQualifier": allowed_qualifiers}},
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))

    session_name = ctx.unique_name("sim2real-sfnalias-")[:64]
    deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
    last = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"AssumeRole on the fresh caller role never succeeded: {last!r}")
    assumed_arn = resp["AssumedRoleUser"]["Arn"]
    creds = resp["Credentials"]
    client = ctx.client("stepfunctions", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    return role_arn, client, assumed_arn


_PROPAGATION_CODES = ("AccessDeniedException", "UnrecognizedClientException")


def _retry_iam_propagation(fn, timeout_s: float = _IAM_RETRY_DEADLINE_S):
    """First use of a freshly assumed session against a freshly attached policy: retry both
    propagation windows (the policy itself, and the session credentials just minted by STS)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _PROPAGATION_CODES:
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"the caller role's policy never took effect: {last!r}")


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
