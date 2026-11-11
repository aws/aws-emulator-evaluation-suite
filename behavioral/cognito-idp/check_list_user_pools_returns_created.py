"""list-user-pools-returns-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-user-pools-returns-created"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUserPools enumerates pools created in the account/region (account-scoped bookkeeping)."""
    idp = ctx.client("cognito-idp")

    pool_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    name_a = ctx.unique_name("sim2real-behav-listpools-a-")
    name_b = ctx.unique_name("sim2real-behav-listpools-b-")
    pool_a = idp.create_user_pool(PoolName=name_a, UserPoolTags=pool_tags)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_a))
    pool_b = idp.create_user_pool(PoolName=name_b, UserPoolTags=pool_tags)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_b))

    found = _list_all_pools(idp)
    found_by_id = {p["Id"]: p["Name"] for p in found}

    assert pool_a in found_by_id and found_by_id[pool_a] == name_a, (
        f"expected ListUserPools to show {pool_a}={name_a!r}, got {found_by_id.get(pool_a)!r}"
    )
    assert pool_b in found_by_id and found_by_id[pool_b] == name_b, (
        f"expected ListUserPools to show {pool_b}={name_b!r}, got {found_by_id.get(pool_b)!r}"
    )
    # Each listed pool entry is a distinct account-scoped resource, not a duplicate/alias.
    assert pool_a != pool_b, f"two separate CreateUserPool calls returned the same id {pool_a!r}"


def _list_all_pools(idp, page_size=60, max_pages=50):
    pools = []
    token = None
    for _ in range(max_pages):
        kwargs = {"MaxResults": page_size}
        if token:
            kwargs["NextToken"] = token
        resp = idp.list_user_pools(**kwargs)
        pools.extend(resp.get("UserPools", []))
        token = resp.get("NextToken")
        if not token:
            break
    return pools


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
