"""get-open-id-token-for-developer-identity-idempotent."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-idempotent"
GROUP = 'developer-identity'
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
    """Same developer user identifier repeatedly resolves to the same IdentityId, confirmed by an independent DescribeIdentity read."""
    ev = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = _create_pool(
        ev,
        ctx,
        allow_unauth=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )
    user_id = ctx.unique_name("sim2real-behav-devuser-")
    resp1 = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_id}
    )
    identity_id = resp1["IdentityId"]
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=[identity_id]))

    resp2 = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_id}
    )
    assert resp2["IdentityId"] == identity_id, (
        f"same developer user identifier must resolve to the same IdentityId: "
        f"{identity_id!r} != {resp2['IdentityId']!r}"
    )
    assert resp1.get("Token") and resp2.get("Token"), (
        f"both calls must vend a non-empty Token, got {resp1.get('Token')!r} and {resp2.get('Token')!r}"
    )

    described = ev.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, (
        f"DescribeIdentity must independently confirm the identity minted by "
        f"GetOpenIdTokenForDeveloperIdentity: expected {identity_id!r}, got {described['IdentityId']!r}"
    )
    assert dev_provider in described.get("Logins", []), (
        f"DescribeIdentity must reflect the developer login used to mint the token: expected "
        f"{dev_provider!r} in Logins, got {described.get('Logins')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
