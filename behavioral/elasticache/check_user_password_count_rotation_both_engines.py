"""user-password-count-rotation-both-engines."""
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

def _wait_user_status(ec, user_id, status, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_one(ec.describe_users, "Users", "UserId", user_id),
        lambda item: item is not None and item.get("Status") == status,
        timeout_s, interval_s,
    )

def _wait_deleted(ec, user_id, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_one(ec.describe_users, "Users", "UserId", user_id),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _delete_user_idempotent(ec, user_id):
    """Teardown: delete the user, tolerating one the check already deleted."""
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as exc:
        if _fault_base(exc.response.get("Error", {}).get("Code")) != "UserNotFound":
            raise

CHECK = "user-password-count-rotation-both-engines"
GROUP = 'user'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A password user's Authentication reports PasswordCount 1 on create for both engines;
    ModifyUser moves that count to 2 with two passwords and back to 1 with one; after DeleteUser,
    DescribeUsers and ModifyUser answer UserNotFoundFault while its sibling still describes.
    """
    ec = ctx.client("elasticache")

    users = {}
    for engine in ("redis", "valkey"):
        user_id = ctx.unique_name(f"sim2real-behav-ecu-{engine}-")
        created = ec.create_user(
            UserId=user_id,
            UserName=user_id,
            Engine=engine,
            AccessString="on ~* +@all",
            AuthenticationMode={"Type": "password", "Passwords": [f"SimToReal-{engine}-Rot0-2026x"]},
            Tags=[{"Key": "Name", "Value": user_id}],
        )
        ctx.on_cleanup(lambda u=user_id: _delete_user_idempotent(ec, u))
        assert (created.get("Engine") or "").lower() == engine, created
        assert created["Authentication"]["Type"] == "password", created
        assert created["Authentication"]["PasswordCount"] == 1, created
        users[engine] = user_id

    for engine, user_id in users.items():
        active = _wait_user_status(ec, user_id, "active")
        assert (active.get("Engine") or "").lower() == engine, active
        assert active["Authentication"]["Type"] == "password", active
        assert active["Authentication"]["PasswordCount"] == 1, active

    for engine, user_id in users.items():
        grown = ec.modify_user(
            UserId=user_id,
            Engine=engine,
            AuthenticationMode={
                "Type": "password",
                "Passwords": [f"SimToReal-{engine}-Rot1a-2026x", f"SimToReal-{engine}-Rot1b-2026x"],
            },
        )
        assert grown["Authentication"]["PasswordCount"] == 2, grown
        grown_active = _wait_user_status(ec, user_id, "active")
        assert grown_active["Authentication"]["PasswordCount"] == 2, grown_active

        shrunk = ec.modify_user(
            UserId=user_id,
            Engine=engine,
            AuthenticationMode={"Type": "password", "Passwords": [f"SimToReal-{engine}-Rot2-2026x"]},
        )
        assert shrunk["Authentication"]["PasswordCount"] == 1, shrunk
        shrunk_active = _wait_user_status(ec, user_id, "active")
        assert shrunk_active["Authentication"]["PasswordCount"] == 1, shrunk_active

    deleted_engine = "redis"
    deleted_id = users[deleted_engine]
    sibling_engine = "valkey"
    sibling_id = users[sibling_engine]

    ec.delete_user(UserId=deleted_id)
    _wait_deleted(ec, deleted_id)

    _assert_error(
        lambda: ec.describe_users(UserId=deleted_id),
        ("UserNotFoundFault", f"User {deleted_id} not found."),
    )
    _assert_error(
        lambda: ec.modify_user(UserId=deleted_id, Engine=deleted_engine, AccessString="on ~* +@all"),
        ("UserNotFoundFault", f"User {deleted_id} not found."),
    )

    # The sibling engine's user is unaffected by the other's deletion: a live describe
    # still answers, and its rotated password count still reads back as 1.
    sibling = _describe_one(ec.describe_users, "Users", "UserId", sibling_id)
    assert sibling is not None, f"sibling user {sibling_id} should still describe"
    assert (sibling.get("Engine") or "").lower() == sibling_engine, sibling
    assert sibling["Authentication"]["Type"] == "password", sibling
    assert sibling["Authentication"]["PasswordCount"] == 1, sibling


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
