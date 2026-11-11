"""list-groups-pagination-stable-order-across-pages."""
from __future__ import annotations

from collections import Counter

from behavioral_harness import tags

CHECK = "list-groups-pagination-stable-order-across-pages"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroups pagination (small page size) returns the exact same groups, in the exact
    same order, as a single unpaginated listing -- no duplicates, no skips -- and repeated
    paginated traversals (with no intervening writes) are stable."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-lg-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-lg"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    names = []
    for i in range(7):
        name = ctx.unique_name(f"sim2real-lg-grp-{i:02d}-")
        cognito.create_group(GroupName=name, UserPoolId=pool_id)
        names.append(name)

    full = _list_all_groups(cognito, pool_id, page_limit=60)
    assert Counter(full) == Counter(names), "single-page listing missed or duplicated groups"

    paginated_first = _list_all_groups(cognito, pool_id, page_limit=2)
    paginated_second = _list_all_groups(cognito, pool_id, page_limit=2)

    assert Counter(paginated_first) == Counter(names), "paginated traversal skipped or duplicated groups"
    assert paginated_first == paginated_second, (
        "ListGroups pagination order changed across two identical, unmodified traversals"
    )
    assert paginated_first == full, (
        "paginated traversal order does not match the single-page traversal order"
    )


def _list_all_groups(cognito, pool_id, page_limit):
    names = []
    next_token = None
    while True:
        kwargs = {"UserPoolId": pool_id, "Limit": page_limit}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cognito.list_groups(**kwargs)
        names.extend(group["GroupName"] for group in resp["Groups"])
        next_token = resp.get("NextToken")
        if not next_token:
            return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
