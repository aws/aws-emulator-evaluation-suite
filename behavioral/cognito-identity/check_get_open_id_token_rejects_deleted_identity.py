"""get-open-id-token-rejects-deleted-identity."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-rejects-deleted-identity"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises, so a
    target that mints a token for a deleted identity fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive guard: token issuance must fail for an identity that was deleted."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    token = ev.get_open_id_token(IdentityId=identity_id)["Token"]
    assert token, f"positive control: GetOpenIdToken returned no token for a live identity {identity_id!r}"
    ev.delete_identities(IdentityIdsToDelete=[identity_id])
    _deadline = time.monotonic() + 30
    last = None
    while time.monotonic() < _deadline:
        try:
            last = ev.get_open_id_token(IdentityId=identity_id)
        except ClientError:
            break
        time.sleep(2)
    else:
        raise AssertionError(f"GetOpenIdToken still minted a token 30s after the delete: {last!r}")
    code, message = _error(lambda: ev.get_open_id_token(IdentityId=identity_id))
    assert code == "ResourceNotFoundException", (
        f"GetOpenIdToken must not mint tokens for a deleted identity, got {code}"
    )
    expected = f"Identity '{identity_id}' not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
