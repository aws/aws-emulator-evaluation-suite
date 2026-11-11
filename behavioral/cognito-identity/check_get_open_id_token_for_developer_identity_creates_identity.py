"""get-open-id-token-for-developer-identity-creates-identity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-creates-identity"
GROUP = "state"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity creates a new identity linked to the developer login."""
    ci = ctx.client("cognito-identity")
    dev_provider = "login.sim2real.devcreate"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user_id = ctx.unique_name("user-devcreate-")
    resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: dev_user_id},
    )
    identity_id = resp["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    assert resp["Token"], f"expected a non-empty Token, got {resp.get('Token')!r}"
    assert identity_id.split(":")[0] == pool_id.split(":")[0], (
        f"identity {identity_id!r} is not scoped to pool {pool_id!r}"
    )

    described = ci.describe_identity(IdentityId=identity_id)
    assert dev_provider in described.get("Logins", []), (
        f"expected {dev_provider} in Logins, got {described.get('Logins')}"
    )

    other_user_id = ctx.unique_name("user-devcreate-other-")
    other_resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: other_user_id},
    )
    other_identity_id = other_resp["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[other_identity_id]))
    assert other_identity_id != identity_id, (
        f"a distinct developer user must get a distinct identity, both resolved to {identity_id!r}"
    )
    other_described = ci.describe_identity(IdentityId=other_identity_id)
    assert dev_provider in other_described.get("Logins", []), (
        f"expected {dev_provider} in Logins, got {other_described.get('Logins')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
