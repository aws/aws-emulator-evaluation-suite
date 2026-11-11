"""list-users-pagination."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-users-pagination"
GROUP = 'pagination'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers honours Limit and pages through the full set via PaginationToken."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    expected: set[str] = set()
    for _ in range(3):
        u = ctx.unique_name("sim2real-behav-cip-user-")
        c.admin_create_user(UserPoolId=pool_id, Username=u, MessageAction="SUPPRESS")
        ctx.on_cleanup(lambda _p=pool_id, _u=u: c.admin_delete_user(UserPoolId=_p, Username=_u))
        expected.add(u)

    _deadline = time.monotonic() + 60
    while time.monotonic() < _deadline:
        visible = {u["Username"] for u in c.list_users(UserPoolId=pool_id)["Users"]}
        if expected <= visible:
            break
        time.sleep(2)
    else:
        raise AssertionError("not all 3 created users visible in ListUsers")

    seen: list[str] = []
    token = None
    pages = 0
    while pages < 10:
        kwargs = {"UserPoolId": pool_id, "Limit": 1}
        if token:
            kwargs["PaginationToken"] = token
        resp = c.list_users(**kwargs)
        pages += 1
        assert len(resp["Users"]) <= 1, (
            f"expected at most 1 user per page with Limit=1, got {len(resp['Users'])}"
        )
        seen.extend(u["Username"] for u in resp["Users"])
        token = resp.get("PaginationToken")
        if not token:
            break

    assert len(seen) == len(set(seen)), (
        f"ListUsers pagination returned duplicates: {sorted(seen)!r}"
    )
    assert set(seen) == expected, (
        "ListUsers pagination lost or fabricated users: "
        f"missing={expected - set(seen)!r} extra={set(seen) - expected!r}"
    )
    assert pages == 3, f"expected exactly 3 pages with Limit=1 and 3 users, got {pages}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
