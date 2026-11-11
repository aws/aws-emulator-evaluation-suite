"""developer-identity-repeated-login-resolves-same-identity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "developer-identity-repeated-login-resolves-same-identity"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeating GetOpenIdTokenForDeveloperIdentity with the same developer user resolves to the same identity."""
    ci = ctx.client("cognito-identity")
    dev_provider = "login.sim2real.devidem"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user_id = ctx.unique_name("user-idem-")
    first = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_id}
    )
    second = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user_id}
    )

    assert first["IdentityId"] == second["IdentityId"], (
        "same developer user identifier must resolve to the same identity on repeated calls: "
        f"first={first['IdentityId']!r} second={second['IdentityId']!r}"
    )
    # Tokens are per-call and should still be independently valid/non-empty.
    assert first["Token"], "first call returned an empty Token"
    assert second["Token"], "second call returned an empty Token"

    # Terminal read: confirm the resolved identity through a different, non-mutating
    # operation rather than trusting GetOpenIdTokenForDeveloperIdentity's own echo twice.
    looked_up = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dev_user_id, MaxResults=1
    )
    assert looked_up["IdentityId"] == first["IdentityId"], (
        "LookupDeveloperIdentity resolved a different identity than the repeated logins: "
        f"lookup={looked_up['IdentityId']!r} logins={first['IdentityId']!r}"
    )
    assert dev_user_id in looked_up.get("DeveloperUserIdentifierList", []), (
        f"expected {dev_user_id!r} in {looked_up.get('DeveloperUserIdentifierList')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
