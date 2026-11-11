"""set-identity-pool-roles-overwrite-semantics."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-overwrite-semantics"
GROUP = 'roles'
SERVICES = ['cognito-identity']

def _cognito_trust_policy(pool_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
            }
        ],
    }

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _role_arn(iam_client, ctx, pool_id, slot="auth"):
    """Create a real IAM role Cognito Identity can pass; register delete cleanup; return its ARN."""
    role_name = f"sim2real-behav-role-{slot}-{uuid.uuid4().hex[:8]}"[:60]
    arn = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_cognito_trust_policy(pool_id)),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_role(RoleName=role_name))
    return arn

def _set_roles(client, pool_id, roles, timeout_s=60, **kwargs):
    """SetIdentityPoolRoles with bounded retry for IAM role propagation delay (transient codes only)."""
    transient = {
        "AccessDeniedException",
        "InvalidParameterException",
        "ThrottlingException",
        "TooManyRequestsException",
        "ConcurrentModificationException",
    }
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles, **kwargs)
        except Exception as exc:  # noqa: BLE001 - propagation races
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in transient or time.monotonic() >= deadline:
                raise
            time.sleep(3)

def _rules_mapping(role_arn: str) -> dict:
    return {
        "graph.facebook.com": {
            "Type": "Rules",
            "AmbiguousRoleResolution": "AuthenticatedRole",
            "RulesConfiguration": {
                "Rules": [
                    {"Claim": "isAdmin", "MatchType": "Equals", "Value": "true", "RoleARN": role_arn}
                ]
            },
        }
    }

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles is a full overwrite (PUT semantics): second call replaces the first entirely."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, 
        allow_unauth=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
    )
    unauth_arn = _role_arn(ctx.client("iam"), ctx, pool_id, "unauth")
    auth_arn = _role_arn(ctx.client("iam"), ctx, pool_id, "auth")
    other_auth_role = _role_arn(ctx.client("iam"), ctx, pool_id, "authalt")
    _set_roles(ev,
        pool_id,
        {"unauthenticated": unauth_arn, "authenticated": auth_arn},
        RoleMappings=_rules_mapping(auth_arn),
    )
    before = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert before["Roles"]["authenticated"] == auth_arn, (
        f"first SetIdentityPoolRoles did not take effect, got {before['Roles']}"
    )
    assert "graph.facebook.com" in before.get("RoleMappings", {}), (
        f"first call's RoleMappings was never persisted, got {before.get('RoleMappings')} — "
        "without this the overwrite assertion below cannot distinguish clearing from never setting"
    )

    _set_roles(ev, pool_id, {"unauthenticated": unauth_arn, "authenticated": other_auth_role})
    got = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert got["Roles"]["authenticated"] == other_auth_role
    assert not got.get("RoleMappings"), (
        f"expected RoleMappings cleared by overwrite, got {got.get('RoleMappings')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
