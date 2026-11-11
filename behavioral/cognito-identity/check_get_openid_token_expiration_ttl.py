"""get-openid-token-expiration-ttl."""
from __future__ import annotations

import base64
import json
import time
import uuid

from behavioral_harness import tags

CHECK = "get-openid-token-expiration-ttl"
GROUP = 'identity-flow'
SERVICES = ['cognito-identity']

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _decode_jwt_claims(token):
    """Decode a JWT's payload (middle segment) WITHOUT verifying the signature -- sufficient for
    asserting on claim shape in a fidelity check."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError(f"not a JWT: {token!r}")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload + padding)
    return json.loads(decoded)

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetOpenIdToken issues an OpenID Connect JWT valid for exactly 10 minutes (600s): the token's
    own exp-iat claims reflect that fixed window and the token is not already expired at issuance."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]

    before = int(time.time())
    got = ev.get_open_id_token(IdentityId=identity_id)
    after = int(time.time())
    claims = _decode_jwt_claims(got["Token"])

    iat = claims["iat"]
    exp = claims["exp"]
    assert before - 5 <= iat <= after + 5, f"unexpected iat {iat} outside [{before}, {after}]"
    ttl = exp - iat
    assert abs(ttl - 600) <= 5, f"expected a ~600s (10 minute) TTL, got {ttl}s (iat={iat}, exp={exp})"
    assert exp > after, f"token expiration {exp} is not in the future relative to issuance ({after})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
