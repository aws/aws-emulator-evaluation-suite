"""list-identity-pools-pagination-stable-ordering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identity-pools-pagination-stable-ordering"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentityPools paged by NextToken returns each created pool exactly once with no repeats
    across pages, and two full traversals with no change to them in between visit them in the same
    order. Other pools in the account are not graded."""
    cognito = ctx.client("cognito-identity")

    created_ids = {_create_pool(ctx) for _ in range(5)}

    order_1 = [i for i in _traverse(cognito) if i in created_ids]
    order_2 = [i for i in _traverse(cognito) if i in created_ids]

    missing = created_ids - set(order_1)
    assert not missing, f"pools created but missing from paginated listing: {missing}"

    for pool_id in created_ids:
        count = order_1.count(pool_id)
        assert count == 1, f"pool {pool_id} appeared {count} times across paginated listing (expected 1)"

    assert order_1 == order_2, (
        "expected two independent full traversals of list_identity_pools (same MaxResults, no "
        f"change to the created pools in between) to visit them in the same order, got "
        f"{order_1!r} vs {order_2!r}"
    )

def _traverse(cognito) -> list[str]:
    seen_ids: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs: dict = {"MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cognito.list_identity_pools(**kwargs)
        seen_ids.extend(p["IdentityPoolId"] for p in resp.get("IdentityPools", []))
        pages += 1
        next_token = resp.get("NextToken")
        if not next_token:
            break
        assert pages < 3000, "pagination did not terminate within a sane number of pages"
    return seen_ids


def _create_pool(ctx, allow_unauth: bool = True) -> str:
    cognito = ctx.client("cognito-identity")
    resp = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool"),
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
