"""list-users-in-group-pagination-stable-order."""
from __future__ import annotations

from collections import Counter

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-users-in-group-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["cognito-idp"]

_NUM_USERS = 12
_PAGE_SIZE = 4


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListUsersInGroup (small page size) returns every member exactly once, in the
    exact same order as a single unpaginated listing -- no duplicates, no omissions -- and two
    successive paginated traversals with no intervening writes return that same order."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-lug-pool"),
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    group_name = ctx.unique_name("sim2real-lug-group")
    cognito.create_group(GroupName=group_name, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_group(GroupName=group_name, UserPoolId=pool_id))

    usernames = [ctx.unique_name(f"sim2real-lug-user-{i}") for i in range(_NUM_USERS)]

    def _cleanup_users():
        for u in usernames:
            try:
                cognito.admin_delete_user(UserPoolId=pool_id, Username=u)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ResourceNotFoundException",
                    "UserNotFoundException",
                ):
                    raise

    ctx.on_cleanup(_cleanup_users)

    for username in usernames:
        cognito.admin_create_user(
            UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS"
        )
        cognito.admin_add_user_to_group(
            UserPoolId=pool_id, Username=username, GroupName=group_name
        )

    full = _list_all(cognito, pool_id, group_name, page_limit=60)
    assert Counter(full) == Counter(usernames), (
        "single-page listing missed, duplicated or added members: "
        f"missing={set(usernames) - set(full)!r} extra={set(full) - set(usernames)!r}"
    )

    paginated_first = _list_all(cognito, pool_id, group_name, page_limit=_PAGE_SIZE)
    paginated_second = _list_all(cognito, pool_id, group_name, page_limit=_PAGE_SIZE)

    assert Counter(paginated_first) == Counter(usernames), (
        "ListUsersInGroup paginated traversal skipped, duplicated or added members: "
        f"missing={set(usernames) - set(paginated_first)!r} extra={set(paginated_first) - set(usernames)!r}"
    )
    assert paginated_first == paginated_second, (
        "ListUsersInGroup pagination order changed across two identical, unmodified traversals: "
        f"first={paginated_first!r} second={paginated_second!r}"
    )
    assert paginated_first == full, (
        "ListUsersInGroup paginated traversal order does not match the single-page traversal order: "
        f"paginated={paginated_first!r} full={full!r}"
    )


def _list_all(cognito, pool_id, group_name, page_limit):
    seen: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {
            "UserPoolId": pool_id,
            "GroupName": group_name,
            "Limit": page_limit,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cognito.list_users_in_group(**kwargs)
        page_users = [u["Username"] for u in resp.get("Users", [])]
        assert len(page_users) <= page_limit, f"page exceeded Limit: {len(page_users)}"
        seen.extend(page_users)
        pages += 1
        next_token = resp.get("NextToken")
        if not next_token:
            return seen
        assert pages < 20, "pagination did not terminate within a sane number of pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
