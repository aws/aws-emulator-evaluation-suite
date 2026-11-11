"""open-id-token-default-expiration-fixed-window."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "open-id-token-default-expiration-fixed-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetOpenIdToken has no TokenDuration parameter at all: its JWT always expires at the
    fixed, undocumented-to-the-caller default window (10 minutes per the API reference),
    consistently across repeated calls for the same identity."""
    cid = ctx.client("cognito-identity")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = cid.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[identity_id]))

    ttls = []
    for _ in range(3):
        resp = cid.get_open_id_token(IdentityId=identity_id)
        claims = _decode_jwt_claims(resp["Token"])
        ttls.append(claims["exp"] - claims["iat"])

    assert all(ttl == 600 for ttl in ttls), (
        f"expected the fixed 600s (10 minute) default window on every call, got {ttls}"
    )


def _decode_jwt_claims(token: str) -> dict:
    import base64
    import json

    parts = token.split(".")
    assert len(parts) == 3, f"expected a 3-part JWT, got {len(parts)} parts: {token!r}"
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + padding))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
