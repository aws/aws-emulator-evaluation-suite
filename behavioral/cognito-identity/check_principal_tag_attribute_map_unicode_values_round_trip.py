"""principal-tag-attribute-map-unicode-values-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "principal-tag-attribute-map-unicode-values-round-trip"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode attribute values set via SetPrincipalTagAttributeMap are returned
    byte-identical from GetPrincipalTagAttributeMap."""
    cognito = ctx.client("cognito-identity")

    provider_name = "graph.facebook.com"
    pool_name = ctx.unique_name("sim2real-idp-")
    created = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={provider_name: "123456789012345"},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    principal_tags = {
        "department": "部門-カスタマーサポート",
        "manager": "Müller-Özdemir",
        "region-name": "Москва/Санкт-Петербург",
        "greeting": "こんにちは😀你好",
    }

    set_resp = cognito.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags=principal_tags,
    )
    assert set_resp["UseDefaults"] is False, (
        f"expected UseDefaults False in the Set response, got {set_resp.get('UseDefaults')!r}"
    )
    assert set_resp["PrincipalTags"] == principal_tags, (
        f"Set response PrincipalTags mismatch: expected {principal_tags!r}, "
        f"got {set_resp['PrincipalTags']!r}"
    )

    got = cognito.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got["UseDefaults"] is False, (
        f"expected UseDefaults False from an independent Get, got {got.get('UseDefaults')!r}"
    )
    assert got["PrincipalTags"] == principal_tags, (
        f"Get response PrincipalTags mismatch: expected {principal_tags!r}, "
        f"got {got['PrincipalTags']!r}"
    )
    for key, value in principal_tags.items():
        assert got["PrincipalTags"][key] == value, (
            f"key {key!r}: expected value {value!r}, got {got['PrincipalTags'].get(key)!r}"
        )
        assert list(got["PrincipalTags"][key]) == list(value), (
            f"key {key!r}: codepoint sequence differs, expected {list(value)!r}, "
            f"got {list(got['PrincipalTags'][key])!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
