"""set-identity-pool-roles-role-mappings-round-trip."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-role-mappings-round-trip"
GROUP = 'credentials'
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

def _poll_until_match(probe, predicate, message, timeout_s=30.0, interval_s=2.0):
    """Bounded poll for a readback to converge; raises (never returns a stale/failure value) on timeout.

    SetIdentityPoolRoles is eventually consistent on real AWS: the very next GetIdentityPoolRoles
    can transiently omit or return stale RoleMappings before propagation completes.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{message}: last read {last}")
        time.sleep(interval_s)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RoleMappings are stored verbatim: GetIdentityPoolRoles echoes the Rules configuration exactly."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx,
        allow_unauth=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
    )
    auth_arn = _role_arn(ctx.client("iam"), ctx, pool_id, "auth")
    mappings = _rules_mapping(auth_arn)
    _set_roles(ev,
        pool_id,
        {"unauthenticated": _role_arn(ctx.client("iam"), ctx, pool_id, "unauth"), "authenticated": auth_arn},
        RoleMappings=mappings,
    )
    got = _poll_until_match(
        lambda: ev.get_identity_pool_roles(IdentityPoolId=pool_id),
        lambda resp: resp.get("RoleMappings", {}) == mappings,
        "RoleMappings never converged to the configured Rules mapping",
    )
    stored = got["RoleMappings"]
    assert "graph.facebook.com" in stored, f"RoleMappings not persisted, got {stored}"
    fb = stored["graph.facebook.com"]
    assert fb["Type"] == "Rules", f"expected Type 'Rules', got {fb['Type']!r}"
    assert fb["AmbiguousRoleResolution"] == "AuthenticatedRole", (
        f"expected AmbiguousRoleResolution 'AuthenticatedRole', got {fb['AmbiguousRoleResolution']!r}"
    )
    rules = fb["RulesConfiguration"]["Rules"]
    assert len(rules) == 1, f"expected exactly the one rule that was written, got {rules}"
    assert rules[0]["Claim"] == "isAdmin", f"expected Claim 'isAdmin', got {rules[0]['Claim']!r}"
    assert rules[0]["MatchType"] == "Equals", f"expected MatchType 'Equals', got {rules[0]['MatchType']!r}"
    assert rules[0]["Value"] == "true", f"expected Value 'true', got {rules[0]['Value']!r}"
    assert rules[0]["RoleARN"] == auth_arn, f"expected RoleARN {auth_arn!r}, got {rules[0]['RoleARN']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
