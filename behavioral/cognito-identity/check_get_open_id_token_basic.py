"""get-open-id-token-basic."""
from __future__ import annotations

import base64
import json
import uuid

from behavioral_harness import tags

CHECK = "get-open-id-token-basic"
GROUP = 'credentials'
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

def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3, f"expected a 3-part JWT, got {len(parts)} parts: {token!r}"
    padding = "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + padding))

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpenIdToken (classic flow) returns a token whose own JWT claims are tied to the
    requesting IdentityId and pool -- not merely a non-empty string."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    resp = ev.get_open_id_token(IdentityId=identity_id)
    assert resp["IdentityId"] == identity_id, (
        f"expected response IdentityId {identity_id!r}, got {resp.get('IdentityId')!r}"
    )
    token = resp.get("Token")
    assert token, "expected a non-empty OpenID token"
    assert len(token) > 20, f"expected a substantial token, got {len(token)} chars: {token!r}"

    claims = _decode_jwt_payload(token)
    assert claims.get("sub") == identity_id, (
        f"JWT sub claim {claims.get('sub')!r} != requesting identity {identity_id!r}"
    )
    assert claims.get("aud") == pool_id, (
        f"JWT aud claim {claims.get('aud')!r} != requesting pool {pool_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
