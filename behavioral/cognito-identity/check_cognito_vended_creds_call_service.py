"""cognito-vended-creds-call-service."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "cognito-vended-creds-call-service"
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
    """Credentials from GetCredentialsForIdentity after SetIdentityPoolRoles sign an STS GetCallerIdentity call
    whose ARN is an assumed-role ARN of the pool's unauthenticated role.
    """
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, IdentityPoolTags={"sim2real": CHECK})
    unauth_arn = _role_arn(iam, ctx, pool_id, "unauth")
    _set_roles(
        ev,
        pool_id,
        {"unauthenticated": unauth_arn, "authenticated": _role_arn(iam, ctx, pool_id, "auth")},
    )
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]

    def _vend():
        try:
            return ev.get_credentials_for_identity(IdentityId=identity_id)
        except Exception:
            return None

    _deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < _deadline:
        resp = _vend()
        if resp is not None:
            break
        time.sleep(3)
    else:
        raise AssertionError("poll condition not met within 90s: GetCredentialsForIdentity")
    assert resp is not None, "GetCredentialsForIdentity never succeeded with roles configured"
    creds = resp["Credentials"]

    # An STS client that signs with the VENDED credentials, not the context's.
    sts = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretKey"],
        "aws_session_token": creds["SessionToken"],
    })

    def _caller():
        try:
            return sts.get_caller_identity()
        except Exception:
            return None

    _deadline = time.monotonic() + 60
    identity = None
    while time.monotonic() < _deadline:
        identity = _caller()
        if identity is not None:
            break
        time.sleep(3)
    else:
        raise AssertionError("poll condition not met within 60s: STS GetCallerIdentity with vended creds")
    assert identity is not None, "the vended credentials could not sign an STS GetCallerIdentity call"

    arn = identity["Arn"]
    role_name = unauth_arn.split("/")[-1]
    assert ":assumed-role/" in arn, f"expected an assumed-role ARN from vended creds, got {arn}"
    assert role_name in arn, (
        f"vended identity {arn} must resolve to the configured unauthenticated role {role_name}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
