"""get-id-anonymous-creates-new-identity-each-call."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "get-id-anonymous-creates-new-identity-each-call"
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
    """GetId without Logins has no dedup key server-side: each call mints a fresh identity,
    independently confirmed via ListIdentities rather than by trusting GetId's own responses."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, IdentityPoolTags={"sim2real": CHECK})
    id1 = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    id2 = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert id1 != id2, "anonymous GetId calls without Logins should not collapse to the same IdentityId"
    for iid in (id1, id2):
        assert iid.startswith(ctx.region + ":"), f"IdentityId {iid} missing region prefix"

    expected_ids = {id1, id2}
    deadline = time.monotonic() + 20
    listed_ids: set[str] = set()
    while time.monotonic() < deadline:
        listed = ev.list_identities(IdentityPoolId=pool_id, MaxResults=60)
        listed_ids = {i["IdentityId"] for i in listed.get("Identities", [])}
        if expected_ids.issubset(listed_ids):
            break
        time.sleep(1)
    else:
        raise AssertionError(
            f"ListIdentities never converged to include both minted identities {expected_ids!r} "
            f"within 20s, last saw {listed_ids!r}"
        )
    assert expected_ids.issubset(listed_ids), (
        f"expected ListIdentities to independently confirm both minted identities {expected_ids!r}, "
        f"got {listed_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
