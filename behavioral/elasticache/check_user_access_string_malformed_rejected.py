"""user-access-string-malformed-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-access-string-malformed-rejected"
GROUP = 'user'
SERVICES = ['elasticache']


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error(fn, what):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what}: expected a ClientError but the call SUCCEEDED (over-permissive)")


def _assert_error(fn, expected, what):
    """Assert fn() fails with the (code, message) pair `expected`, the code Fault/Exception-suffix
    normalized and the message exact."""
    code, actual = _error(fn, what)
    assert _fault_base(code) == _fault_base(expected[0]), (
        f"{what}: expected {expected[0]}, got {code} ({actual!r})"
    )
    assert actual == expected[1], f"{what}: expected message {expected[1]!r}, got {actual!r}"
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
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _describe_user(ec, user_id):
    return _describe_one(ec.describe_users, "Users", "UserId", user_id)


def _wait_user_active(ec, user_id, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_user(ec, user_id),
        lambda u: u is not None and u.get("Status") == "active",
        timeout_s, interval_s,
    )


def _wait_access_string_contains(ec, user_id, needle, timeout_s=300, interval_s=5):
    return _poll(
        lambda: _describe_user(ec, user_id),
        lambda u: (
            u is not None
            and u.get("Status") == "active"
            and needle in (u.get("AccessString") or "")
        ),
        timeout_s, interval_s,
    )


def _delete_user_quietly(ec, user_id):
    """Delete a user, tolerating a user that is already gone or still deleting."""
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as e:
        code = _fault_base(e.response.get("Error", {}).get("Code") or "")
        if code in ("UserNotFound", "InvalidUserState"):
            return
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed ElastiCache RBAC AccessString is refused by ModifyUser and the previously applied
    grant survives, while a well-formed grant still applies; the AccessString grammar is enforced
    only server-side, so storing it verbatim would accept every malformed grant.
    """
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-behav-ecu-access-")

    # ---- valid setup: a narrow, well-formed grant ---------------------------------
    created = ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString="on ~sim2real:* +@read",
        NoPasswordRequired=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_quietly(ec, user_id))
    assert created["UserId"] == user_id, created
    assert created["Authentication"]["Type"] == "no-password", created

    user = _wait_user_active(ec, user_id)
    initial = user.get("AccessString") or ""
    # Real AWS normalises the grant, so assert on the semantic tokens rather than equality.
    assert initial.startswith("on "), f"AccessString must start with the on/off state: {initial!r}"
    assert "~sim2real:*" in initial, f"key pattern was dropped from the grant: {initial!r}"
    assert "+@read" in initial, f"category grant was dropped from the grant: {initial!r}"

    # ---- valid setup, part 2: widen it, so a successful ModifyUser is established ---
    ec.modify_user(UserId=user_id, AccessString="on ~sim2real:* +@read +@write")
    widened = _wait_access_string_contains(ec, user_id, "+@write")
    good_access = widened["AccessString"]
    assert "+@read" in good_access and "+@write" in good_access, good_access

    # ---- break exactly one thing: an unknown command category ----------------------
    _assert_error(
        lambda: ec.modify_user(
            UserId=user_id,
            AccessString="on ~sim2real:* +@sim2realnotacategory",
        ),
        (
            "InvalidParameterValueException",
            "Access string contains invalid category(s). "
            "Please verify the list of available category in user-api.",
        ),
        "AccessString with an unknown command category '+@sim2realnotacategory'",
    )

    # ---- effect absent -------------------------------------------------------------
    after_bad_category = _describe_user(ec, user_id)
    assert after_bad_category is not None, "user vanished after a rejected ModifyUser"
    now = after_bad_category.get("AccessString") or ""
    assert "sim2realnotacategory" not in now, (
        f"REJECTED ModifyUser still wrote the malformed grant: AccessString is now {now!r}"
    )
    assert "+@write" in now and "+@read" in now, (
        f"REJECTED ModifyUser clobbered the previously-applied grant: AccessString is now "
        f"{now!r}, expected it to still be {good_access!r}"
    )
    assert after_bad_category.get("Status") == "active", (
        f"a rejected ModifyUser must leave the user active, got "
        f"{after_bad_category.get('Status')!r}"
    )

    # ---- break exactly one thing: not access-string syntax at all -------------------
    _assert_error(
        lambda: ec.modify_user(
            UserId=user_id,
            AccessString="SIM2REAL THIS IS NOT AN ACCESS STRING",
        ),
        ("InvalidParameterValueException", "The access-string is invalid."),
        "AccessString that is free text rather than RBAC syntax",
    )

    # ---- effect absent, again ------------------------------------------------------
    after_garbage = _describe_user(ec, user_id)
    assert after_garbage is not None, "user vanished after a rejected ModifyUser"
    still = after_garbage.get("AccessString") or ""
    assert "SIM2REAL" not in still and "NOT AN ACCESS STRING" not in still, (
        f"REJECTED ModifyUser stored free text as a grant: AccessString is now {still!r}"
    )
    assert "+@write" in still, (
        f"REJECTED ModifyUser clobbered the previously-applied grant: {still!r}"
    )

    # ---- control case still works: a third well-formed grant applies ---------------
    ec.modify_user(UserId=user_id, AccessString="off ~sim2real:* -@all")
    narrowed = _poll(
        lambda: _describe_user(ec, user_id),
        lambda u: (
            u is not None
            and u.get("Status") == "active"
            and (u.get("AccessString") or "").startswith("off")
        ),
    )
    assert "+@write" not in (narrowed.get("AccessString") or ""), (
        f"control case failed: narrowing the grant did not drop +@write; AccessString is "
        f"{narrowed.get('AccessString')!r}"
    )

    ec.delete_user(UserId=user_id)
    _poll(lambda: _describe_user(ec, user_id), lambda u: u is None)

    # ---- deletes prove gone and unusable: a mutation on the dead id also fails -----
    _assert_error(
        lambda: ec.modify_user(UserId=user_id, AccessString="on ~sim2real:* +@all"),
        ("UserNotFoundFault", f"User {user_id} not found."),
        "ModifyUser on the just-deleted user_id",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
