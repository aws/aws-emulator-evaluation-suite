"""user-lifecycle."""
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

def _wait_deleted(fn, list_key, id_field, id_value, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _describe_user(ec, user_id):
    return _describe_one(ec.describe_users, "Users", "UserId", user_id)

def _wait_user_status(ec, user_id, status, timeout_s=300, interval_s=5):
    return _wait_status(ec.describe_users, "Users", "UserId", user_id, "Status", status, timeout_s, interval_s)

def _wait_user_access_string(ec, user_id, prefix, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_user(ec, user_id),
        lambda u: u is not None and u.get("Status") == "active" and (u.get("AccessString") or "").startswith(prefix),
        timeout_s, interval_s,
    )

def _delete_user_idempotent(ec, user_id):
    """Teardown: delete the user, tolerating one the check already deleted."""
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as exc:
        if _fault_base(exc.response.get("Error", {}).get("Code")) != "UserNotFound":
            raise

CHECK = "user-lifecycle"
GROUP = 'user'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A no-password user becomes active with engine redis, an off access string and no user groups, ModifyUser
    changes its AccessString to on, and once deleted DescribeUsers fails with UserNotFound "User <id> not found."."""
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-behav-ecu-")
    created = ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString="off ~* -@all",
        NoPasswordRequired=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_idempotent(ec, user_id))
    assert created["UserId"] == user_id
    assert created["Authentication"]["Type"] == "no-password", created

    user = _wait_user_status(ec, user_id, "active")
    assert user is not None, "user never reached active"
    assert user["AccessString"].startswith("off"), user
    assert user["Engine"].lower() == "redis", user
    assert user.get("UserGroupIds", []) == [], user

    ec.modify_user(UserId=user_id, AccessString="on ~* +@all")
    updated = _wait_user_access_string(ec, user_id, "on")
    assert updated is not None, "ModifyUser AccessString never took effect"

    ec.delete_user(UserId=user_id)
    _wait_deleted(ec.describe_users, "Users", "UserId", user_id,
                   timeout_s=300, interval_s=5)
    _assert_error(
        lambda: ec.describe_users(UserId=user_id),
        ("UserNotFoundFault", f"User {user_id} not found."),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
