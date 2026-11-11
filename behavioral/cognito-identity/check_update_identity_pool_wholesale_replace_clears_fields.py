"""update-identity-pool-wholesale-replace-clears-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-identity-pool-wholesale-replace-clears-fields"
GROUP = "state"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityPool replaces config wholesale: an omitted optional field is cleared, not preserved."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real_pool_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
        IdentityPoolTags={"env": "test", "owner": "fidelity-check"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    before = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert before.get("SupportedLoginProviders") == {"graph.facebook.com": "1234567890123456"}, (
        f"expected the create-time login provider to be present before update, got {before.get('SupportedLoginProviders')!r}"
    )

    ci.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        # SupportedLoginProviders intentionally omitted -> must be cleared, full replace semantics
    )

    after = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert not after.get("SupportedLoginProviders"), (
        f"expected SupportedLoginProviders cleared by wholesale replace, got {after.get('SupportedLoginProviders')}"
    )
    assert after["IdentityPoolName"] == name, (
        f"expected IdentityPoolName to remain {name!r} after update, got {after['IdentityPoolName']!r}"
    )
    assert after["AllowUnauthenticatedIdentities"] is True, (
        f"expected AllowUnauthenticatedIdentities to remain True after update, got {after['AllowUnauthenticatedIdentities']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
