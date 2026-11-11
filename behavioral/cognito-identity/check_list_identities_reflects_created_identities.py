"""list-identities-reflects-created-identities."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-identities-reflects-created-identities"
GROUP = 'identity-flow'
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
    """ListIdentities enumerates every identity created via GetId under the pool, not just the
    first: three anonymous GetId calls mint three distinct identities (no Logins to dedup on),
    and all three must eventually be visible via the independent ListIdentities read."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    created_ids = {ev.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(3)}
    assert len(created_ids) == 3, f"anonymous GetId unexpectedly reused an IdentityId: {created_ids}"
    ctx.on_cleanup(lambda: ev.delete_identities(IdentityIdsToDelete=list(created_ids)))

    def _missing():
        resp = ev.list_identities(IdentityPoolId=pool_id, MaxResults=60)
        listed_ids = {i["IdentityId"] for i in resp.get("Identities", [])}
        return created_ids - listed_ids

    _deadline = time.monotonic() + 20
    missing = created_ids
    while time.monotonic() < _deadline:
        missing = _missing()
        if not missing:
            break
        time.sleep(1)
    assert not missing, f"created identities never appeared in ListIdentities: {missing}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
