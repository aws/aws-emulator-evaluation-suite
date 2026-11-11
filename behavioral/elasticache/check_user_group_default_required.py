"""user-group-default-required."""
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

CHECK = "user-group-default-required"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserGroup whose UserIds omit 'default' is refused with DefaultUserRequired and its exact message and
    creates no group, while the same membership plus 'default' becomes active with exactly those users."""
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-ecu-nodef-")
    ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString="on ~* +@all",
        NoPasswordRequired=True,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ec.delete_user(UserId=user_id))
    _wait_user_status(ec, user_id, "active")

    # Positive control: the same membership plus 'default' succeeds, so the negative below is
    # attributable to the missing 'default' and not to a broken CreateUserGroup path.
    control_group_id = ctx.unique_name("sim2real-ecug-ctrl-")
    ec.create_user_group(
        UserGroupId=control_group_id, Engine="redis", UserIds=["default", user_id],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ec.delete_user_group(UserGroupId=control_group_id))
    control = _wait_user_group_status(ec, control_group_id, "active")
    assert set(control["UserIds"]) == {"default", user_id}, control

    group_id = ctx.unique_name("sim2real-ecug-nodef-")
    _assert_error(lambda: ec.create_user_group(
        UserGroupId=group_id, Engine="redis", UserIds=[user_id],
    ), ("DefaultUserRequired",
        "Redis user group needs to contain a user with the user name default."))

    # Nothing was created as a side effect of the rejected call.
    assert _describe_user_group(ec, group_id) is None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
