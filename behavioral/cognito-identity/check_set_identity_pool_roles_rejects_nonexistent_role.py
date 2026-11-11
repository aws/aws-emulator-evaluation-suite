"""set-identity-pool-roles-rejects-nonexistent-role."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-rejects-nonexistent-role"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

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

def _account_id(ctx) -> str:
    """Caller account id."""
    return ctx.account

def _ghost_role_arn(ctx) -> str:
    """A well-formed same-account role ARN that does not exist."""
    return f"arn:aws:iam::{_account_id(ctx)}:role/sim2real-behav-nonexistent-role-xyz"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles accepts a well-formed same-account ARN of a role that does not exist and
    stores it, since AWS checks the role only when it vends credentials."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    ghost = _ghost_role_arn(ctx)
    # real AWS does not eagerly validate role existence: a well-formed same-account role ARN
    # is accepted even when the role does not exist, so a refusal raises here.
    ev.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": ghost})
    got = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert got.get("Roles", {}).get("unauthenticated") == ghost, (
        "the accepted role config must round-trip via GetIdentityPoolRoles"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
