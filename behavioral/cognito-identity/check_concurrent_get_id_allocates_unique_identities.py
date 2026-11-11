"""concurrent-get-id-allocates-unique-identities."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-get-id-allocates-unique-identities"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent unauthenticated GetId calls against the same pool allocate N distinct identity
    IDs, independently confirmed enumerable via ListIdentities at the destination."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    n = 12

    def _get_id() -> str:
        return ci.get_id(IdentityPoolId=pool_id)["IdentityId"]

    results = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_get_id) for _ in range(n)]
        for fut in as_completed(futures):
            results.append(fut.result())

    assert len(results) == n, f"expected {n} GetId calls to complete, got {len(results)}"
    assert len(set(results)) == n, (
        f"expected {n} unique identity ids under concurrency, got {len(set(results))}: {results}"
    )

    def _list_all() -> set[str]:
        seen: set[str] = set()
        token = None
        for _ in range(10):
            kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
            if token:
                kwargs["NextToken"] = token
            page = ci.list_identities(**kwargs)
            seen.update(i["IdentityId"] for i in page.get("Identities", []))
            token = page.get("NextToken")
            if not token:
                break
        return seen

    ids = set(results)
    deadline = time.monotonic() + 30
    listed: set[str] = set()
    while time.monotonic() < deadline:
        listed = _list_all()
        if ids.issubset(listed):
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"expected all {n} concurrently-allocated identities visible via an independent "
            f"ListIdentities read within 30s, missing {ids - listed}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
