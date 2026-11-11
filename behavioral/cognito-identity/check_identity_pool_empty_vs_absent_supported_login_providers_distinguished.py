"""identity-pool-empty-vs-absent-supported-login-providers-distinguished."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-pool-empty-vs-absent-supported-login-providers-distinguished"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SupportedLoginProviders set to an empty map is omitted on create and DescribeIdentityPool,
    exactly like a pool that never set it, while a non-empty map is preserved on read."""
    cognito = ctx.client("cognito-identity")

    pool_explicit_empty = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-idp-explicit-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id_explicit = pool_explicit_empty["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id_explicit))

    pool_absent = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-idp-absent-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id_absent = pool_absent["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id_absent))

    described_explicit = cognito.describe_identity_pool(IdentityPoolId=pool_id_explicit)
    described_absent = cognito.describe_identity_pool(IdentityPoolId=pool_id_absent)

    assert "SupportedLoginProviders" not in pool_explicit_empty, (
        f"expected CreateIdentityPool to omit SupportedLoginProviders for an "
        f"explicit empty map, got {pool_explicit_empty.get('SupportedLoginProviders')!r}"
    )
    assert "SupportedLoginProviders" not in described_explicit, (
        f"expected DescribeIdentityPool to omit SupportedLoginProviders for the "
        f"explicit-empty-map pool, got {described_explicit.get('SupportedLoginProviders')!r}"
    )
    assert "SupportedLoginProviders" not in described_absent, (
        f"expected DescribeIdentityPool to omit SupportedLoginProviders for the "
        f"pool that never set it, got {described_absent.get('SupportedLoginProviders')!r}"
    )

    # Only the empty map collapses; DescribeIdentityPool does not drop the field wholesale.
    pool_nonempty = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-idp-nonempty-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "000000000000000"},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id_nonempty = pool_nonempty["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id_nonempty))
    described_nonempty = cognito.describe_identity_pool(IdentityPoolId=pool_id_nonempty)
    assert described_nonempty["SupportedLoginProviders"] == {
        "graph.facebook.com": "000000000000000"
    }, (
        f"expected a non-empty SupportedLoginProviders map to round-trip unchanged, "
        f"got {described_nonempty.get('SupportedLoginProviders')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

