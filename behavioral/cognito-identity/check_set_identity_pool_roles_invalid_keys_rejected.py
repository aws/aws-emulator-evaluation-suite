"""set-identity-pool-roles-invalid-keys-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-invalid-keys-rejected"
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

def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles must reject Roles maps using keys other than authenticated/unauthenticated."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    auth_arn = _role_arn(ctx.client("iam"), ctx, pool_id, "auth")
    _set_roles(ev, pool_id, {"authenticated": auth_arn})
    err, message = _error(
        lambda: ev.set_identity_pool_roles(
            IdentityPoolId=pool_id,
            Roles={"admin": auth_arn},
        )
    )
    assert err == "ValidationException", (
        f"expected ValidationException for invalid Roles key, got {err}"
    )
    assert message == (
        f"1 validation error detected: Value '{{admin={auth_arn}}}' at 'roles' failed to satisfy "
        "constraint: Map keys must satisfy constraint: [Member must have length less than or "
        "equal to 128, Member must have length greater than or equal to 1, Member must satisfy "
        "regular expression pattern: (un)?authenticated]"
    ), (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )
    got = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert got["Roles"].get("authenticated") == auth_arn, (
        f"expected the pre-existing authenticated role mapping {auth_arn!r} to survive the "
        f"rejected call, got {got['Roles']!r}"
    )
    assert "admin" not in got["Roles"], f"invalid role key was persisted: {got['Roles']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
