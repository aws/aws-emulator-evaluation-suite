"""list-users-filter-exact-set-semantics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-users-filter-exact-set-semantics"
GROUP = "list-users-filter"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_BAD_FILTER = ("InvalidParameterException", "Input fails to satisfy the constraints.")


def _seed_user(ctx, c, pool_id: str, email: str) -> tuple[str, str]:
    """Create a confirmed user with an email attribute; return (username, sub)."""
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    sub = next(
        a["Value"] for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
        if a["Name"] == "sub"
    )
    return username, sub


def _list_until_exact(c, pool_id: str, filter_expr: str, expected: set[str], deadline_s: float = 60.0) -> None:
    """Poll ListUsers with ``filter_expr`` until its usernames equal ``expected`` exactly."""
    deadline = time.monotonic() + deadline_s
    seen: set[str] = set()
    while time.monotonic() < deadline:
        seen = {u["Username"] for u in c.list_users(UserPoolId=pool_id, Filter=filter_expr)["Users"]}
        if seen == expected:
            return
        time.sleep(2)
    raise AssertionError(
        f"filter {filter_expr!r} did not settle on {sorted(expected)!r}; last saw {sorted(seen)!r}"
    )


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListUsers Filter returns the exact matching set for a prefix, an exact email and a sub
    query, an empty result with no PaginationToken on no match, and rejects a filter on a
    non-searchable attribute with its exact message.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    user_a, _sub_a = _seed_user(ctx, c, pool_id, "alpha@x.example")
    user_b, _sub_b = _seed_user(ctx, c, pool_id, "alpha-beta@x.example")
    user_c, sub_c = _seed_user(ctx, c, pool_id, "gamma@y.example")

    _list_until_exact(c, pool_id, 'email ^= "alpha"', {user_a, user_b})
    _list_until_exact(c, pool_id, 'email = "alpha@x.example"', {user_a})
    _list_until_exact(c, pool_id, f'sub = "{sub_c}"', {user_c})

    resp = c.list_users(UserPoolId=pool_id, Filter='email = "nobody@x.example"')
    assert resp["Users"] == [], f"expected no users for a non-matching filter, got {resp['Users']!r}"
    assert "PaginationToken" not in resp, (
        f"expected no PaginationToken on an empty result, got {resp.get('PaginationToken')!r}"
    )

    _expect_error(lambda: c.list_users(UserPoolId=pool_id, Filter='gender = "x"'), *_BAD_FILTER)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
