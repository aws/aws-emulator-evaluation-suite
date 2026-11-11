"""modify-user-conflicting-auth-params-rejected."""
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

def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a rejection but the call SUCCEEDED")

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

CHECK = "modify-user-conflicting-auth-params-rejected"
GROUP = 'user'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyUser rejects NoPasswordRequired with a password AuthenticationMode as
    InvalidParameterCombination, leaving the user's password auth untouched; an ordinary
    ModifyUser on the same user still succeeds."""
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-behav-ecu-conflict-")

    created = ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString="on ~* +@all",
        Passwords=["SimToRealConflictPass-One-2026"],
        Tags=[{"Key": "Name", "Value": user_id}],
    )
    ctx.on_cleanup(lambda: _delete_user_if_present(ec, user_id))
    assert created["Authentication"]["Type"] == "password", created
    assert created["Authentication"]["PasswordCount"] == 1, created
    _wait_user_status(ec, user_id, "active")

    code, message = _error(
        lambda: ec.modify_user(
            UserId=user_id,
            NoPasswordRequired=True,
            AuthenticationMode={"Type": "password", "Passwords": ["SimToRealConflictPass-Two-2026"]},
        )
    )
    assert _fault_base(code) == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {code}")
    expected = "No password required flag is true but provided authentication type is password"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = ec.describe_users(UserId=user_id)["Users"][0]
    assert unchanged["Authentication"]["Type"] == "password", unchanged
    assert unchanged["Authentication"]["PasswordCount"] == 1, unchanged

    # Positive control: the rejection is about the combination, not an unmodifiable user.
    control = ec.modify_user(UserId=user_id, AccessString="on ~* -@all +@read")
    assert control["AccessString"] == "on ~* -@all +@read", control
    confirmed = _wait_user_status(ec, user_id, "active")
    assert confirmed["AccessString"] == "on ~* -@all +@read", confirmed

    ec.delete_user(UserId=user_id)
    _poll(
        lambda: _fault_base(_error_code(lambda: ec.describe_users(UserId=user_id))),
        lambda base: base == _fault_base("UserNotFoundFault"),
        timeout_s=300, interval_s=5,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
