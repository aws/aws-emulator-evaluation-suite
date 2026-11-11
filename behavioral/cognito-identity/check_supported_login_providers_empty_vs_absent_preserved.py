"""supported-login-providers-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "supported-login-providers-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityPool omits SupportedLoginProviders for a pool created with an empty map and
    for one created without it, and returns the map unchanged for a pool created with one provider."""
    ci = ctx.client("cognito-identity")

    pool_with_empty_map = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-empty-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_with_empty_map))

    pool_without_field = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-absent-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_without_field))

    pool_with_providers = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-nonempty-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "000000000000001"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_with_providers))

    described_empty = ci.describe_identity_pool(IdentityPoolId=pool_with_empty_map)
    described_absent = ci.describe_identity_pool(IdentityPoolId=pool_without_field)
    described_with_providers = ci.describe_identity_pool(IdentityPoolId=pool_with_providers)

    # AWS treats an explicitly empty map like an absent field: both are omitted from the
    # response rather than returned as {}.
    assert "SupportedLoginProviders" not in described_empty, (
        f"expected an explicitly empty SupportedLoginProviders map to be normalized "
        f"to an absent field, got {described_empty.get('SupportedLoginProviders')!r}"
    )
    assert "SupportedLoginProviders" not in described_absent, (
        f"expected SupportedLoginProviders to be entirely absent, got "
        f"{described_absent.get('SupportedLoginProviders')!r}"
    )
    # Positive control: a non-empty map is preserved and returned, so the omissions above are
    # specific to the empty and absent cases.
    assert described_with_providers.get("SupportedLoginProviders") == {
        "graph.facebook.com": "000000000000001"
    }, (
        f"expected a non-empty SupportedLoginProviders map to round-trip intact, "
        f"got {described_with_providers.get('SupportedLoginProviders')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

