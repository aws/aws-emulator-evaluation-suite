"""get-credentials-for-identity-full-flow."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-full-flow"
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
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
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

@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Enhanced flow end-to-end: GetId -> SetIdentityPoolRoles -> GetCredentialsForIdentity yields usable STS creds."""
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    account_id = ctx.account
    pool_id = _create_pool(ev, ctx, allow_unauth=True, IdentityPoolTags={"sim2real-check": CHECK})
    unauth_arn = _role_arn(iam, ctx, pool_id, "unauth")
    auth_arn = _role_arn(iam, ctx, pool_id, "auth")
    for arn in (unauth_arn, auth_arn):
        iam.tag_role(RoleName=arn.rsplit("/", 1)[-1], Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    unauth_role_name = unauth_arn.rsplit("/", 1)[-1]
    _set_roles(ev, pool_id, {"unauthenticated": unauth_arn, "authenticated": auth_arn})
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert identity_id.startswith(f"{ctx.region}:"), (
        f"expected IdentityId to start with {ctx.region + ':'!r}, got {identity_id!r}"
    )
    # Only the codes a just-created role's IAM propagation produces are retried; anything else
    # (a 5xx, an unexpected code) fails at once.
    propagation = {"InvalidIdentityPoolConfigurationException", "AccessDeniedException", "InvalidParameterException"}

    def _vend():
        try:
            return ev.get_credentials_for_identity(IdentityId=identity_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in propagation:
                raise
            return None
    _deadline = time.monotonic() + 90
    r = None
    while time.monotonic() < _deadline:
        r = _vend()
        if r is not None:
            break
        time.sleep(3)
    else:
        raise AssertionError(f"poll condition not met within {90}s: {r!r}")
    resp = r
    assert resp is not None, "GetCredentialsForIdentity never succeeded with roles configured"
    assert resp["IdentityId"] == identity_id, f"expected IdentityId {identity_id!r}, got {resp['IdentityId']!r}"
    creds = resp["Credentials"]
    assert creds.get("AccessKeyId"), "expected AccessKeyId in vended credentials"
    assert creds.get("SecretKey"), "expected SecretKey in vended credentials"
    assert creds.get("SessionToken"), "expected SessionToken in vended credentials"
    assert "Expiration" in creds, "expected Expiration in vended credentials"

    # Presence of the fields is not enough: the terminal read is an independent call, at the
    # destination, using the vended creds themselves — not the harness's own STS client.
    caller = _boto_sts_with_creds(ctx, creds).get_caller_identity()
    assert caller["Account"] == account_id, (
        f"vended creds resolved to account {caller['Account']!r}, expected {account_id!r}"
    )
    arn_prefix = f"arn:aws:sts::{account_id}:assumed-role/{unauth_role_name}/"
    arn_ok = caller["Arn"].startswith(arn_prefix) and len(caller["Arn"]) > len(arn_prefix)
    assert arn_ok, (
        f"vended creds resolved to {caller['Arn']!r}, expected an assumed-role session ARN under "
        "the unauthenticated role in this account"
    )


def _boto_sts_with_creds(ctx, creds: dict):
    """An STS client on this run's target, signed with the vended credentials."""
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
