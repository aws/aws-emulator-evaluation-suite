"""list-identities-pagination-complete-and-disjoint."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-identities-pagination-complete-and-disjoint"
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

@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentities pagination with MaxResults=1 walks every identity exactly once."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    created = {ev.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(3)}
    assert len(created) == 3, f"expected 3 distinct identity ids from GetId, got {len(created)}: {created!r}"
    def _walk():
        seen: list[str] = []
        token = None
        for _ in range(10):
            kwargs = {"IdentityPoolId": pool_id, "MaxResults": 1}
            if token:
                kwargs["NextToken"] = token
            page = ev.list_identities(**kwargs)
            ids = [i["IdentityId"] for i in page.get("Identities", [])]
            assert len(ids) <= 1, f"MaxResults=1 must cap the page size, got {len(ids)}"
            seen.extend(ids)
            token = page.get("NextToken")
            if not token:
                break
        return seen
    _deadline = time.monotonic() + 30
    s = None
    while time.monotonic() < _deadline:
        s = _walk()
        if created.issubset(set(s)):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"poll condition not met within {30}s: {s!r}")
    seen = s
    assert created.issubset(set(seen)), f"pagination missed identities: expected {created}, saw {seen}"
    assert len(seen) == len(set(seen)), f"pagination returned duplicates: {seen}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
