"""get-open-id-token-for-developer-identity-max-duration-boundary-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-max-duration-boundary-accepted"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TokenDuration set to exactly the documented maximum (86400s) is accepted, and the
    resulting JWT's exp-iat equals exactly that duration -- confirming an inclusive upper
    boundary rather than an off-by-one rejection."""
    cid = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    dev_user_id = ctx.unique_name("sim2real-user-")
    resp = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider: dev_user_id},
        TokenDuration=86400,
    )
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[resp["IdentityId"]]))

    claims = _decode_jwt_claims(resp["Token"])
    ttl = claims["exp"] - claims["iat"]
    assert ttl == 86400, f"expected exp-iat == 86400 at the max-duration boundary, got {ttl}"


def _decode_jwt_claims(token: str) -> dict:
    import base64
    import json

    payload = token.split(".")[1]
    padding = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + padding))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
