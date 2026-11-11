"""user-group-not-found-semantics."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, got = err.get("Code"), err.get("Message")
    else:
        raise AssertionError(f"expected {expected[0]} but the call SUCCEEDED")
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert got == expected[1], f"{code}: expected message {expected[1]!r}, got {got!r}"
    return code

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _poll(probe, predicate, timeout_s=300, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _describe_user_group(ec, group_id):
    return _describe_one(ec.describe_user_groups, "UserGroups", "UserGroupId", group_id)

def _wait_user_status(ec, user_id, status, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_one(ec.describe_users, "Users", "UserId", user_id),
        lambda u: u is not None and u.get("Status") == status,
        timeout_s, interval_s,
    )

def _wait_group_membership(ec, group_id, expected_ids, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_user_group(ec, group_id),
        lambda g: g is not None and g.get("Status") == "active" and set(g.get("UserIds", [])) == expected_ids,
        timeout_s, interval_s,
    )

def _delete_user_group_idempotent(ec, group_id):
    try:
        ec.delete_user_group(UserGroupId=group_id)
    except ClientError as exc:
        if _fault_base(exc.response.get("Error", {}).get("Code")) != "UserGroupNotFound":
            raise

def _delete_user_idempotent(ec, user_id):
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as exc:
        if _fault_base(exc.response.get("Error", {}).get("Code")) != "UserNotFound":
            raise

CHECK = "user-group-not-found-semantics"
GROUP = 'user-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """User-group reads/mutations for an unknown UserGroupId raise UserGroupNotFound -- and the
    identical describe/modify/delete calls succeed against a real, live group, so the refusal is
    attributable to the missing id and not to a blanket denial of these three operations."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-ecug-missing-")

    user_id = ctx.unique_name("sim2real-behav-ecu-ugnf-")
    ec.create_user(
        UserId=user_id, UserName=user_id, Engine="redis",
        AccessString="on ~* +@all", NoPasswordRequired=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_idempotent(ec, user_id))
    _wait_user_status(ec, user_id, "active")

    group_id = ctx.unique_name("sim2real-behav-ecug-real-")
    ec.create_user_group(
        UserGroupId=group_id, Engine="redis", UserIds=["default", user_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_group_idempotent(ec, group_id))

    # Positive control: describe and modify succeed on a real, live group id.
    group = _wait_group_membership(ec, group_id, {"default", user_id})
    assert group["UserGroupId"] == group_id, group

    ec.modify_user_group(UserGroupId=group_id, UserIdsToRemove=[user_id])
    _wait_group_membership(ec, group_id, {"default"})

    # Negative: the identical three calls against an id that was never created.
    _assert_error(
        lambda: ec.describe_user_groups(UserGroupId=bogus),
        ("UserGroupNotFoundFault", f"User group {bogus} not found."),
    )
    _assert_error(
        lambda: ec.modify_user_group(UserGroupId=bogus, UserIdsToAdd=["default"]),
        ("UserGroupNotFoundFault", f"User group {bogus} not found."),
    )
    _assert_error(
        lambda: ec.delete_user_group(UserGroupId=bogus),
        ("UserGroupNotFoundFault", f"User group {bogus} not found."),
    )

    # The real group, once actually deleted, is gone by an independent read and unusable by a
    # mutation -- the same not-found semantics the negative above already claims.
    ec.delete_user_group(UserGroupId=group_id)
    _poll(
        lambda: _describe_user_group(ec, group_id),
        lambda g: g is None,
        300, 5,
    )
    assert _describe_user_group(ec, group_id) is None
    _assert_error(
        lambda: ec.modify_user_group(UserGroupId=group_id, UserIdsToAdd=["default"]),
        ("UserGroupNotFoundFault", f"User group {group_id} not found."),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
