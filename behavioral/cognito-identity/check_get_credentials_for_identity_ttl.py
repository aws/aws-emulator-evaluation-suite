"""get-credentials-for-identity-ttl."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-ttl"
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

@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity's Credentials.Expiration is a real STS session expiry consistent
    with the assumed role's default 1-hour maximum session duration -- comfortably in the future,
    and bounded well below any absurdly long or already-expired value."""
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    unauth_role_arn = _role_arn(iam, ctx, pool_id, "unauth")
    auth_role_arn = _role_arn(iam, ctx, pool_id, "auth")
    _set_roles(ev, pool_id, {"authenticated": auth_role_arn, "unauthenticated": unauth_role_arn})

    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]

    def _try_get_credentials():
        try:
            return ev.get_credentials_for_identity(IdentityId=identity_id)
        except Exception as exc:  # noqa: BLE001 -- role/trust-policy propagation lag
            return exc

    before = time.time()
    _deadline = time.monotonic() + 45
    result = None
    while time.monotonic() < _deadline:
        result = _try_get_credentials()
        if not isinstance(result, Exception):
            break
        time.sleep(3)
    else:
        raise AssertionError(f"newly configured identity pool roles never became usable: {result!r}")
    after = time.time()
    creds = result["Credentials"]

    expiration = creds["Expiration"].timestamp()
    ttl_from_before = expiration - before
    ttl_from_after = expiration - after

    assert ttl_from_after > 0, f"expected Expiration {expiration} to be in the future (now={after})"
    # The role was created with no explicit MaxSessionDuration, so IAM's default
    # (1 hour) applies; allow generous tolerance around that.
    assert 600 <= ttl_from_before <= 3900, (
        f"expected an STS session TTL close to the role's 1-hour default, got {ttl_from_before}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
