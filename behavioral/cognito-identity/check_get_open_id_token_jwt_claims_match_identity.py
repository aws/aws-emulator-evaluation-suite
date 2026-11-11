"""get-open-id-token-jwt-claims-match-identity."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "get-open-id-token-jwt-claims-match-identity"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpenIdToken returns a JWS whose sub/aud claims tie back to the requesting identity and pool."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    before = time.time()
    resp = ci.get_open_id_token(IdentityId=identity_id)
    assert resp["IdentityId"] == identity_id, (
        f"GetOpenIdToken echoed IdentityId {resp['IdentityId']!r} != {identity_id!r}"
    )
    token = resp["Token"]

    parts = token.split(".")
    assert len(parts) == 3, f"expected a 3-segment JWS, got {len(parts)} segments"

    payload = json.loads(_b64url_decode(parts[1]))
    assert payload["sub"] == identity_id, f"sub claim {payload.get('sub')!r} != identity {identity_id!r}"
    assert payload["aud"] == pool_id, f"aud claim {payload.get('aud')!r} != pool {pool_id!r}"
    exp = payload.get("exp")
    assert isinstance(exp, (int, float)) and exp > before, (
        f"exp claim {exp!r} must be a unix timestamp after the token was issued ({before!r})"
    )


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
