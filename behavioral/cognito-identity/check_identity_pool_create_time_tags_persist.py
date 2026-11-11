"""identity-pool-create-time-tags-persist."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "identity-pool-create-time-tags-persist"
GROUP = 'pool-config'
SERVICES = ['cognito-identity']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied at CreateIdentityPool are echoed by the create response and persist verbatim in
    DescribeIdentityPool; a pool created without tags has no tag map, and an unrelated
    UpdateIdentityPool does NOT clear previously assigned tags."""
    ev = ctx.client("cognito-identity")

    untagged_name = f"sim2real-behav-pool-notags-{uuid.uuid4().hex[:8]}".replace("-", "_")
    untagged = ev.create_identity_pool(
        IdentityPoolName=untagged_name, AllowUnauthenticatedIdentities=True
    )
    untagged_id = untagged["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=untagged_id))
    untagged_desc = ev.describe_identity_pool(IdentityPoolId=untagged_id)
    assert untagged_desc.get("IdentityPoolTags", {}) == {}, (
        f"expected no tags on an untagged pool, got {untagged_desc.get('IdentityPoolTags')}"
    )

    name = f"sim2real-behav-pool-tags-{uuid.uuid4().hex[:8]}".replace("-", "_")
    resp = ev.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"env": "test", "owner": "fidelity-check"},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=pool_id))
    assert resp.get("IdentityPoolTags") == {"env": "test", "owner": "fidelity-check"}, (
        f"expected CreateIdentityPool to echo the tags, got {resp.get('IdentityPoolTags')}"
    )

    desc = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc.get("IdentityPoolTags") == {"env": "test", "owner": "fidelity-check"}, (
        f"expected create-time tags to persist verbatim, got {desc.get('IdentityPoolTags')}"
    )

    new_name = f"sim2real-behav-pool-tags-renamed-{uuid.uuid4().hex[:8]}".replace("-", "_")
    ev.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=new_name,
        AllowUnauthenticatedIdentities=False,
    )
    after = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert after["IdentityPoolName"] == new_name
    assert after.get("IdentityPoolTags") == {"env": "test", "owner": "fidelity-check"}, (
        f"expected tags to survive an unrelated UpdateIdentityPool, got {after.get('IdentityPoolTags')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
