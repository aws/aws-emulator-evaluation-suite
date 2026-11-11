"""get-identity-pool-roles-default-empty."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-default-empty"
GROUP = 'roles'
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

def _ghost_role_arn(ctx) -> str:
    """A well-formed, same-account role ARN that names no real role. Real AWS's
    SetIdentityPoolRoles accepts and persists this without eagerly checking that the role
    exists, so it is enough to prove GetIdentityPoolRoles tracks real per-pool state."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-ghost-{uuid.uuid4().hex[:8]}"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityPoolRoles on a new pool returns no Roles, and after SetIdentityPoolRoles it
    returns exactly the configured unauthenticated role, so the empty answer is the pool's real
    state."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)

    got = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert got["IdentityPoolId"] == pool_id, f"expected IdentityPoolId {pool_id}, got {got['IdentityPoolId']}"
    assert not got.get("Roles"), f"expected no roles configured yet, got {got.get('Roles')}"

    ghost = _ghost_role_arn(ctx)
    ev.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": ghost})
    configured = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert configured.get("Roles") == {"unauthenticated": ghost}, (
        f"expected the just-configured role to round-trip, got {configured.get('Roles')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
