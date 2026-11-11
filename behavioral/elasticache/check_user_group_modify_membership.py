"""user-group-modify-membership."""
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

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _wait_user_status(ec, user_id, status, timeout_s=300, interval_s=5):
    return _wait_status(ec.describe_users, "Users", "UserId", user_id, "Status", status, timeout_s, interval_s)

def _describe_user_group(ec, group_id):
    return _describe_one(ec.describe_user_groups, "UserGroups", "UserGroupId", group_id)

def _wait_user_group_status(ec, group_id, status, timeout_s=300, interval_s=5):
    return _wait_status(ec.describe_user_groups, "UserGroups", "UserGroupId", group_id, "Status", status, timeout_s, interval_s)

CHECK = "user-group-modify-membership"
GROUP = 'user-group'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyUserGroup adding one user and removing another leaves exactly {default, added}; a duplicate group id is
    refused with UserGroupAlreadyExists and its exact message, and after deletion a modify fails with
    UserGroupNotFound "User group <id> not found." while the id can be created again."""
    ec = ctx.client("elasticache")
    user_a = ctx.unique_name("sim2real-behav-ecu-grpa-")
    user_b = ctx.unique_name("sim2real-behav-ecu-grpb-")
    for uid in (user_a, user_b):
        ec.create_user(
            UserId=uid, UserName=uid, Engine="redis",
            AccessString="on ~* +@all", NoPasswordRequired=True,
        )
        ctx.on_cleanup(lambda uid=uid: ec.delete_user(UserId=uid))
        _wait_user_status(ec, uid, "active")

    group_id = ctx.unique_name("sim2real-behav-ecug-mod-")
    created = ec.create_user_group(
        UserGroupId=group_id, Engine="redis", UserIds=["default", user_a],
    )
    ctx.on_cleanup(lambda: ec.delete_user_group(UserGroupId=group_id))
    assert created["Status"] in ("creating", "active"), created["Status"]

    group = _wait_user_group_status(ec, group_id, "active")
    assert set(group["UserIds"]) == {"default", user_a}, group

    ec.modify_user_group(
        UserGroupId=group_id, UserIdsToAdd=[user_b], UserIdsToRemove=[user_a],
    )
    group = _poll(
        lambda: _describe_user_group(ec, group_id),
        lambda g: g is not None and g.get("Status") == "active"
        and set(g.get("UserIds", [])) == {"default", user_b},
        300, 5,
    )
    assert set(group["UserIds"]) == {"default", user_b}

    # Duplicate group id is rejected while the group still exists (state forbids, not the input).
    _assert_error(lambda: ec.create_user_group(
        UserGroupId=group_id, Engine="redis", UserIds=["default"],
    ), ("UserGroupAlreadyExistsFault",
        f"User group {group_id} already exists. Please retry with another name."))

    ec.delete_user_group(UserGroupId=group_id)
    _poll(
        lambda: _describe_user_group(ec, group_id),
        lambda g: g is None,
        300, 5,
    )

    # Gone means unusable: a mutation on the now-dead id fails with the specific not-found code.
    _assert_error(lambda: ec.modify_user_group(
        UserGroupId=group_id, UserIdsToAdd=["default"],
    ), ("UserGroupNotFoundFault", f"User group {group_id} not found."))

    # Restore leg: the identical create rejected above now succeeds — the id is reusable.
    recreated = ec.create_user_group(
        UserGroupId=group_id, Engine="redis", UserIds=["default"],
    )
    assert recreated["Status"] in ("creating", "active"), recreated["Status"]
    _wait_user_group_status(ec, group_id, "active")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
