"""update-pool-put-overwrite-semantics."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-pool-put-overwrite-semantics"
GROUP = 'lifecycle'
SERVICES = ['cognito-identity']

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityPool is a full PUT-style overwrite, not a merge: omitted fields clear."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, 
        allow_unauth=True,
        SupportedLoginProviders={"graph.facebook.com": "fb-app-id-123"},
    )
    desc = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc.get("SupportedLoginProviders") == {"graph.facebook.com": "fb-app-id-123"}, (
        f"expected create-time SupportedLoginProviders to persist, got {desc.get('SupportedLoginProviders')!r}"
    )
    updated = ev.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=desc["IdentityPoolName"],
        AllowUnauthenticatedIdentities=False,
    )
    assert updated["AllowUnauthenticatedIdentities"] is False, (
        f"expected UpdateIdentityPool's own response to report AllowUnauthenticatedIdentities=False, "
        f"got {updated['AllowUnauthenticatedIdentities']!r}"
    )
    assert not updated.get("SupportedLoginProviders"), (
        f"expected SupportedLoginProviders cleared by PUT semantics, got {updated.get('SupportedLoginProviders')}"
    )
    redesc = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert redesc["AllowUnauthenticatedIdentities"] is False, (
        f"expected an independent DescribeIdentityPool to confirm AllowUnauthenticatedIdentities=False, "
        f"got {redesc['AllowUnauthenticatedIdentities']!r}"
    )
    assert not redesc.get("SupportedLoginProviders"), (
        f"expected SupportedLoginProviders still cleared on independent read, got {redesc.get('SupportedLoginProviders')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
