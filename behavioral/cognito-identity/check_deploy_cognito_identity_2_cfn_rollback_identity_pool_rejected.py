"""deploy-cognito-identity-2-cfn-rollback-identity-pool-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-identity-2-cfn-rollback-identity-pool-rejected"
GROUP = "deploy-cfn-rollback-identity-pool"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose Rules role mapping lacks RulesConfiguration rolls back and deletes the pool it
    created; a refused in-place DeveloperProviderName update leaves the control pool unchanged.
    """
    cfn = ctx.client("cloudformation")
    cog = ctx.client("cognito-identity")

    # A fictitious (but well-formed) user-pool provider: CreateIdentityPool does not
    # resolve it, and a role mapping must name a provider that is registered on the pool.
    user_pool_id = f"{ctx.region}_AbCdEfGhI"
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    client_id = "abcdefghijklmnopqrstuvwxyz"

    ok_stack = ctx.unique_name("sim2real-cfn-cip-ok-")
    bad_stack = ctx.unique_name("sim2real-cfn-cip-bad-")
    ok_dev = ctx.unique_name("sim2real.dev.ok.")
    bad_dev = ctx.unique_name("sim2real.dev.bad.")
    ok_template = _template(
        pool_name=ctx.unique_name("sim2real_cip_ok_").replace("-", "_"),
        developer_provider=ok_dev,
        provider_name=provider_name,
        client_id=client_id,
        mapping={"Type": "Token", "AmbiguousRoleResolution": "AuthenticatedRole"},
    )
    bad_template = _template(
        pool_name=ctx.unique_name("sim2real_cip_bad_").replace("-", "_"),
        developer_provider=bad_dev,
        provider_name=provider_name,
        client_id=client_id,
        # the ONE broken thing: Rules with no RulesConfiguration
        mapping={"Type": "Rules", "AmbiguousRoleResolution": "AuthenticatedRole"},
    )

    # Launch both stacks together; each delete is registered right after its create.
    _create_stack(ctx, cfn, ok_stack, ok_template)
    _create_stack(ctx, cfn, bad_stack, bad_template)

    # --- control stack: the positive half of the twin ---
    ok_status = _wait_terminal(cfn, ok_stack)
    assert ok_status == "CREATE_COMPLETE", (
        f"control stack with a valid Token role mapping must reach CREATE_COMPLETE, got "
        f"{ok_status!r}; events: {_event_summary(cfn, ok_stack)!r}"
    )
    ok_pool_id = _outputs(cfn, ok_stack)["IdentityPoolId"]

    # --- failing stack: attachment fails, the whole stack rolls back ---
    bad_status = _wait_terminal(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack whose role attachment has Type=Rules and no RulesConfiguration must end "
        f"ROLLBACK_COMPLETE, got {bad_status!r}; events: {_event_summary(cfn, bad_stack)!r}"
    )
    events = _events(cfn, bad_stack)
    failed = [e for e in events if e["ResourceStatus"] == "CREATE_FAILED"]
    assert [(e["LogicalResourceId"], e["ResourceType"]) for e in failed] == [
        ("RoleAttachment", "AWS::Cognito::IdentityPoolRoleAttachment")
    ], (
        f"exactly the role attachment must be CREATE_FAILED, got "
        f"{[(e['LogicalResourceId'], e['ResourceType'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    assert "RuleConfiguration is required for Rules" in reason, (
        f"attachment failure reason must name the missing rules configuration, got {reason!r}"
    )
    rollback_reasons = [
        e.get("ResourceStatusReason") or ""
        for e in events
        if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
    ]
    assert len(rollback_reasons) == 1 and "[RoleAttachment]" in rollback_reasons[0], (
        f"the stack's ROLLBACK_IN_PROGRESS reason must name the attachment, got {rollback_reasons!r}"
    )

    # The pool WAS created before the attachment failed; its id is in the events.
    pool_ids = {
        e["PhysicalResourceId"]
        for e in events
        if e["LogicalResourceId"] == "IdentityPool"
        and e["ResourceStatus"] == "CREATE_COMPLETE"
        and e.get("PhysicalResourceId")
    }
    assert len(pool_ids) == 1, (
        f"expected exactly one IdentityPool CREATE_COMPLETE PhysicalResourceId in the failing "
        f"stack's events, got {sorted(pool_ids)!r}"
    )
    bad_pool_id = pool_ids.pop()
    assert bad_pool_id != ok_pool_id, f"twin stacks share a pool id {bad_pool_id!r}"
    for logical in ("IdentityPool", "AuthRole"):
        deleted = [e for e in events
                   if e["LogicalResourceId"] == logical and e["ResourceStatus"] == "DELETE_COMPLETE"]
        assert len(deleted) == 1, (
            f"rollback must delete {logical} exactly once, got statuses "
            f"{[e['ResourceStatus'] for e in events if e['LogicalResourceId'] == logical]!r}"
        )

    # Effect absent: the rolled-back pool is gone through the pool's OWN API.
    code = _error(lambda: cog.describe_identity_pool(IdentityPoolId=bad_pool_id))
    expected = ("ResourceNotFoundException", f"IdentityPool '{bad_pool_id}' not found.")
    assert code == expected, (
        f"DescribeIdentityPool on the rolled-back pool {bad_pool_id!r} must be "
        f"{expected!r}, got {code!r}"
    )
    listed = _list_pool_ids(cog)
    assert bad_pool_id not in listed, (
        f"rolled-back pool {bad_pool_id!r} is still listed by ListIdentityPools"
    )
    # Positive control in the same walk: the control stack's pool is listed.
    assert ok_pool_id in listed, (
        f"control pool {ok_pool_id!r} missing from ListIdentityPools ({len(listed)} pools walked)"
    )

    # --- control stack: a DeveloperProviderName change the service refuses in place ---
    before = cog.describe_identity_pool(IdentityPoolId=ok_pool_id)
    assert before["DeveloperProviderName"] == ok_dev, (
        f"control pool DeveloperProviderName expected {ok_dev!r}, got "
        f"{before.get('DeveloperProviderName')!r}"
    )
    # The control attachment's RoleMappings are live on the pool: with role mappings
    # configured the service refuses developer-token minting outright.
    code = _error(lambda: cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=ok_pool_id, Logins={ok_dev: "sim2real-user-1"}))
    expected = (
        "InvalidParameterException",
        "Invalid identity pool configuration. When a pool is configured for RoleMappings,"
        " GetOpenIdTokenForDeveloperIdentity may not be used.",
    )
    assert code == expected, (
        f"GetOpenIdTokenForDeveloperIdentity on a pool whose CFN attachment set RoleMappings "
        f"must be {expected!r}, got {code!r}"
    )
    roles = cog.get_identity_pool_roles(IdentityPoolId=ok_pool_id)
    mapping_keys = sorted(roles.get("RoleMappings", {}))
    assert mapping_keys == [f"{provider_name}:{client_id}"], (
        f"control pool RoleMappings expected one Token mapping for the provider, got {mapping_keys!r}"
    )

    new_dev = ctx.unique_name("sim2real.dev.new.")
    updated_template = json.loads(ok_template)
    updated_template["Resources"]["IdentityPool"]["Properties"]["DeveloperProviderName"] = new_dev
    seen_event_ids = {e["EventId"] for e in _events(cfn, ok_stack)}
    cfn.update_stack(StackName=ok_stack, TemplateBody=json.dumps(updated_template),
                     Capabilities=["CAPABILITY_IAM"])
    upd_status = _wait_terminal(cfn, ok_stack)
    assert upd_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"changing DeveloperProviderName on an existing pool must roll the update back, got "
        f"{upd_status!r}; events: {_event_summary(cfn, ok_stack)!r}"
    )
    upd_events = [e for e in _events(cfn, ok_stack) if e["EventId"] not in seen_event_ids]
    upd_failed = [e for e in upd_events if e["ResourceStatus"] == "UPDATE_FAILED"]
    assert [(e["LogicalResourceId"], e.get("PhysicalResourceId")) for e in upd_failed] == [
        ("IdentityPool", ok_pool_id)
    ], (
        f"exactly the IdentityPool must be UPDATE_FAILED, in place on {ok_pool_id!r}, got "
        f"{[(e['LogicalResourceId'], e.get('PhysicalResourceId'), e.get('ResourceStatusReason')) for e in upd_failed]!r}"
    )

    after = cog.describe_identity_pool(IdentityPoolId=ok_pool_id)
    assert after["IdentityPoolId"] == ok_pool_id, after
    assert after["DeveloperProviderName"] == ok_dev, (
        f"after the rolled-back update DeveloperProviderName must still be {ok_dev!r}, got "
        f"{after.get('DeveloperProviderName')!r}"
    )
    assert _outputs(cfn, ok_stack)["IdentityPoolId"] == ok_pool_id, "stack output pool id changed"

    after_roles = cog.get_identity_pool_roles(IdentityPoolId=ok_pool_id)
    assert sorted(after_roles.get("RoleMappings", {})) == mapping_keys, (
        f"the rolled-back update disturbed the attachment's RoleMappings: "
        f"{sorted(after_roles.get('RoleMappings', {}))!r}"
    )

    # The pool still honours the ORIGINAL developer provider: a merge naming it is
    # accepted as far as the (unknown) users ...
    code = _error(lambda: cog.merge_developer_identities(
        SourceUserIdentifier="sim2real-user-1", DestinationUserIdentifier="sim2real-user-2",
        DeveloperProviderName=ok_dev, IdentityPoolId=ok_pool_id))
    expected = ("ResourceNotFoundException", "User 'sim2real-user-1' not found.")
    assert code == expected, (
        f"MergeDeveloperIdentities under the original provider {ok_dev!r} must fail only on the "
        f"unknown user ({expected!r}), got {code!r}"
    )
    # ... while the provider the update proposed was never registered.
    code = _error(lambda: cog.merge_developer_identities(
        SourceUserIdentifier="sim2real-user-1", DestinationUserIdentifier="sim2real-user-2",
        DeveloperProviderName=new_dev, IdentityPoolId=ok_pool_id))
    expected = (
        "InvalidParameterException",
        "This identity pool does not support the specified developer provider.",
    )
    assert code == expected, (
        f"MergeDeveloperIdentities under the rejected provider name {new_dev!r} must be "
        f"{expected!r}, got {code!r}"
    )


_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "UPDATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(*, pool_name, developer_provider, provider_name, client_id, mapping) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "IdentityPool": {
                "Type": "AWS::Cognito::IdentityPool",
                "Properties": {
                    "IdentityPoolName": pool_name,
                    "AllowUnauthenticatedIdentities": False,
                    "DeveloperProviderName": developer_provider,
                    "CognitoIdentityProviders": [{
                        "ProviderName": provider_name,
                        "ClientId": client_id,
                        "ServerSideTokenCheck": False,
                    }],
                },
            },
            "AuthRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "cognito-identity.amazonaws.com:aud": {"Ref": "IdentityPool"}
                                },
                                "ForAnyValue:StringLike": {
                                    "cognito-identity.amazonaws.com:amr": "authenticated"
                                },
                            },
                        }],
                    },
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "RoleAttachment": {
                "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "Roles": {"authenticated": {"Fn::GetAtt": ["AuthRole", "Arn"]}},
                    "RoleMappings": {
                        "userpool": dict({"IdentityProvider": f"{provider_name}:{client_id}"},
                                         **mapping),
                    },
                },
            },
        },
        "Outputs": {"IdentityPoolId": {"Value": {"Ref": "IdentityPool"}}},
    })


def _create_stack(ctx, cfn, name: str, body: str) -> None:
    cfn.create_stack(
        StackName=name,
        TemplateBody=body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, name))


def _delete_stack(cfn, name: str) -> None:
    try:
        cfn.delete_stack(StackName=name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"cloudformation stack {name}: {exc!r}") from exc


def _wait_terminal(cfn, name: str, timeout_s: float = 600.0) -> str:
    """Poll the stack to a terminal status (waiters raise on ROLLBACK_COMPLETE, which is
    an expected outcome here)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {name} never reached a terminal status; last {status!r}")


def _events(cfn, name: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page["StackEvents"])
    return out


def _event_summary(cfn, name: str) -> list:
    return [(e["LogicalResourceId"], e["ResourceStatus"], (e.get("ResourceStatusReason") or "")[:160])
            for e in _events(cfn, name)][:15]


def _outputs(cfn, name: str) -> dict:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _list_pool_ids(cog) -> set:
    ids, token = set(), None
    while True:
        kwargs = {"MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        resp = cog.list_identity_pools(**kwargs)
        ids.update(p["IdentityPoolId"] for p in resp.get("IdentityPools", []))
        token = resp.get("NextToken")
        if not token:
            return ids


def _error(fn):
    """Call fn(); return its ClientError's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
