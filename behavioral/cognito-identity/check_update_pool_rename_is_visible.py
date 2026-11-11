"""update-pool-rename-is-visible."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-pool-rename-is-visible"
GROUP = 'pool-config'
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityPool renames in place: the id is stable and Describe reflects the new name."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    new_name = ctx.unique_name("sim2real-behav-renamed-").replace("-", "_")
    updated = ev.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=new_name,
        AllowUnauthenticatedIdentities=True,
    )
    assert updated["IdentityPoolId"] == pool_id, "rename must not mint a new pool id"
    assert updated["IdentityPoolName"] == new_name, (
        f"expected UpdateIdentityPool response to echo the new name {new_name!r}, "
        f"got {updated['IdentityPoolName']!r}"
    )
    desc = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc["IdentityPoolName"] == new_name, f"rename not reflected in Describe: {desc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
