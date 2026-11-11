"""developer-user-identifier-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "developer-user-identifier-unicode-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A developer user identifier containing unicode characters is preserved
    exactly and resolvable via LookupDeveloperIdentity."""
    cognito = ctx.client("cognito-identity")

    developer_provider_name = ctx.unique_name("sim2real-dev-")
    pool_name = ctx.unique_name("sim2real-idp-")
    created = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider_name,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    developer_user_identifier = "用户-Ïñtérnâtiônàlizætiøn-Δοκιμή-42"

    token_resp = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={developer_provider_name: developer_user_identifier},
    )
    identity_id = token_resp["IdentityId"]
    ctx.on_cleanup(
        lambda: cognito.delete_identities(IdentityIdsToDelete=[identity_id])
    )

    lookup = cognito.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=1
    )
    assert lookup["IdentityId"] == identity_id, (
        f"expected LookupDeveloperIdentity to resolve {identity_id!r}, got "
        f"{lookup.get('IdentityId')!r}"
    )
    assert developer_user_identifier in lookup["DeveloperUserIdentifierList"], (
        f"expected {developer_user_identifier!r} in "
        f"{lookup['DeveloperUserIdentifierList']!r}"
    )
    matched = next(
        u for u in lookup["DeveloperUserIdentifierList"] if u == developer_user_identifier
    )
    assert matched.encode("utf-8") == developer_user_identifier.encode("utf-8"), (
        f"expected the returned identifier's UTF-8 bytes to match the submitted "
        f"identifier's bytes exactly, got {matched.encode('utf-8')!r} vs "
        f"{developer_user_identifier.encode('utf-8')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
