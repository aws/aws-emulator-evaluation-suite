"""user-access-string-append-and-password-mode-switch."""
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

def _error_code(fn):
    """Call fn(); return the botocore Error.Code if a ClientError was raised, else "OK"."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "OK"

def _delete_user_if_present(ec, user_id):
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as e:
        if _fault_base(e.response.get("Error", {}).get("Code") or "") != "UserNotFound":
            raise

def _poll(probe, predicate, timeout_s=300, interval_s=5):
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
        lambda: ec.describe_users(UserId=user_id)["Users"][0],
        lambda u: u.get("Status") == status,
        timeout_s, interval_s,
    )

CHECK = "user-access-string-append-and-password-mode-switch"
GROUP = 'user'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AppendAccessString extends a user's AccessString rather than replacing it, and switching a
    password user to NoPasswordRequired reads back type "no-password" with PasswordCount 0 while
    the appended AccessString survives."""
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-behav-ecu-append-")
    base_access_string = "on ~app:* -@all +@read"

    created = ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString=base_access_string,
        Passwords=["SimToRealAppendPass-One-2026"],
        Tags=[{"Key": "Name", "Value": user_id}],
    )
    ctx.on_cleanup(lambda: _delete_user_if_present(ec, user_id))
    assert created["Authentication"]["Type"] == "password", created
    assert created["Authentication"]["PasswordCount"] == 1, created
    _wait_user_status(ec, user_id, "active")

    appended = ec.modify_user(UserId=user_id, AppendAccessString="+@write")
    expected_appended = base_access_string + " +@write"
    assert appended["AccessString"] == expected_appended, appended

    after_append = _wait_user_status(ec, user_id, "active")
    assert after_append["AccessString"] == expected_appended, after_append
    assert after_append["Authentication"]["Type"] == "password", after_append

    # Reads report the output enum "no-password"; "no-password-required" is only an input value.
    opened = ec.modify_user(UserId=user_id, NoPasswordRequired=True)
    assert opened["Authentication"]["Type"] == "no-password", opened
    assert opened["Authentication"].get("PasswordCount", 0) == 0, opened

    after_switch = _wait_user_status(ec, user_id, "active")
    assert after_switch["Authentication"]["Type"] == "no-password", after_switch
    assert after_switch["Authentication"].get("PasswordCount", 0) == 0, after_switch
    assert after_switch["AccessString"] == expected_appended, after_switch

    ec.delete_user(UserId=user_id)
    _poll(
        lambda: _fault_base(_error_code(lambda: ec.describe_users(UserId=user_id))),
        lambda base: base == _fault_base("UserNotFoundFault"),
        timeout_s=300, interval_s=5,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
