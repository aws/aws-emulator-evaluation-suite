"""concurrent-get-id-creates-distinct-identities."""
from __future__ import annotations

import concurrent.futures
import time
import uuid

from behavioral_harness import tags

CHECK = "concurrent-get-id-creates-distinct-identities"
GROUP = 'concurrency'
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

def _run_concurrent(fns):
    """Run callables in parallel; return results 1:1 in submission order (exceptions captured, not raised)."""
    results = [None] * len(fns)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns))) as ex:
        fut_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                results[i] = exc
    return results

@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent anonymous GetId calls all succeed and each mints a distinct IdentityId."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)

    n = 8
    fns = [lambda: ev.get_id(IdentityPoolId=pool_id) for _ in range(n)]
    results = _run_concurrent(fns)

    n_success = sum(1 for r in results if not isinstance(r, BaseException))
    assert n_success == n, f"expected all {n} concurrent GetId calls to succeed, got {n_success}"

    ids = {r["IdentityId"] for r in results if isinstance(r, dict)}
    assert len(ids) == n, f"concurrent GetId collapsed identities: {ids}"

    def _all_listed():
        seen = set()
        token = None
        for _ in range(10):
            kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
            if token:
                kwargs["NextToken"] = token
            page = ev.list_identities(**kwargs)
            seen.update(i["IdentityId"] for i in page.get("Identities", []))
            token = page.get("NextToken")
            if not token:
                break
        return seen

    _deadline = time.monotonic() + 45
    seen = None
    while time.monotonic() < _deadline:
        seen = _all_listed()
        if len(seen) >= n:
            break
        time.sleep(3)
    else:
        raise AssertionError(f"poll condition not met within 45s: {seen!r}")
    assert seen is not None and len(seen) >= n, (
        f"expected at least {n} identities in the pool after concurrent GetId, saw {len(seen or [])}"
    )
    assert ids.issubset(seen), "identities returned by GetId must be enumerable via ListIdentities"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
