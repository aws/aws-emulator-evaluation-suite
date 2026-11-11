"""update-identity-pool-full-replacement-clears-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-identity-pool-full-replacement-clears-fields"
GROUP = "lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityPool uses full-replacement semantics: an omitted field is cleared, not left unchanged."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    created = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    assert created.get("SupportedLoginProviders") == {"graph.facebook.com": "1234567890123456"}, (
        f"expected CreateIdentityPool to echo SupportedLoginProviders, got {created.get('SupportedLoginProviders')!r}"
    )

    # Update WITHOUT SupportedLoginProviders -- full-replacement semantics must clear it,
    # while fields that ARE present in the request (name, unauth flag) must survive untouched --
    # otherwise a target that just wipes the whole record would pass too.
    updated = ci.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
    )
    assert not updated.get("SupportedLoginProviders"), (
        f"expected SupportedLoginProviders cleared by omission, got {updated.get('SupportedLoginProviders')!r}"
    )
    assert updated.get("IdentityPoolName") == name, (
        f"expected IdentityPoolName preserved across the replacement, got {updated.get('IdentityPoolName')!r}"
    )
    assert updated.get("AllowUnauthenticatedIdentities") is True, (
        f"expected AllowUnauthenticatedIdentities preserved across the replacement, got {updated.get('AllowUnauthenticatedIdentities')!r}"
    )

    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert not described.get("SupportedLoginProviders"), (
        f"expected SupportedLoginProviders cleared after update, got {described.get('SupportedLoginProviders')!r}"
    )
    assert described.get("IdentityPoolName") == name, (
        f"expected IdentityPoolName preserved after update, got {described.get('IdentityPoolName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
