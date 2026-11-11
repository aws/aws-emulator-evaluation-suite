"""get-open-id-token-for-developer-identity-token-ttl-matches-requested-duration."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-token-ttl-matches-requested-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The TokenDuration passed to GetOpenIdTokenForDeveloperIdentity is reflected in the actual
    exp-iat span of the returned OpenID token, not just clamped to the default 15 minutes."""
    ci = ctx.client("cognito-identity")

    dev_provider_name = ctx.unique_name("sim2real-behav-dev-")
    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider_name,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    requested_duration_s = 3600  # distinct from the 900s default

    token_resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider_name: ctx.unique_name("sim2real-behav-user-")},
        TokenDuration=requested_duration_s,
    )
    claims = _decode_jwt_claims(token_resp["Token"])
    actual_ttl_s = claims["exp"] - claims["iat"]

    # exp-iat is computed server-side in the same response as an exact integer duration, so the
    # emulator must reproduce the requested TokenDuration exactly, not clamp to the 900s default nor
    # merely land within some window of it.
    assert actual_ttl_s == requested_duration_s, (
        f"token TTL {actual_ttl_s}s does not exactly match the requested TokenDuration={requested_duration_s}s "
        f"(iat={claims['iat']}, exp={claims['exp']})"
    )


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _decode_jwt_claims(token: str) -> dict:
    parts = token.split(".")
    return json.loads(_b64url_decode(parts[1]))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
