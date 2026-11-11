"""default-user-exists-and-is-immutable."""
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

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, got = _error(fn, expected[0])
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert got == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {got!r}"
    return code

def _describe_user(ec, user_id):
    users = ec.describe_users(Engine="redis")["Users"]
    return next((u for u in users if u["UserId"] == user_id), None)

def _poll(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

CHECK = "default-user-exists-and-is-immutable"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The engine-managed 'default' user is listed active with UserName default, and DeleteUser on it is refused with
    InvalidParameterValue "default user can't be deleted." leaving it active, while a user the check creates deletes."""
    ec = ctx.client("elasticache")
    users = ec.describe_users(Engine="redis")["Users"]
    default = next((u for u in users if u["UserId"] == "default"), None)
    assert default is not None, "no engine-managed 'default' user"
    assert default["Status"] == "active", default
    assert default["UserName"] == "default", default

    # Positive control: DeleteUser works at all, on a real customer-created user. Without this,
    # the InvalidParameterValueException below cannot be told apart from "DeleteUser always fails".
    control_id = ctx.unique_name("sim2real-behav-ecu-ctrl-")
    ec.create_user(
        UserId=control_id,
        UserName=control_id,
        Engine="redis",
        AccessString="off ~* -@all",
        NoPasswordRequired=True,
    )
    control_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if control_deleted["done"] else ec.delete_user(UserId=control_id))
    _poll(
        lambda: _describe_user(ec, control_id),
        lambda u: u is not None and u.get("Status") == "active",
        timeout_s=300, interval_s=5,
    )
    ec.delete_user(UserId=control_id)
    _poll(
        lambda: _describe_user(ec, control_id),
        lambda u: u is None,
        timeout_s=300, interval_s=5,
    )
    control_deleted["done"] = True
    assert _describe_user(ec, control_id) is None, "control user still present after DeleteUser"

    # The default user is not a customer-deletable resource.
    _assert_error(
        lambda: ec.delete_user(UserId="default"),
        ("InvalidParameterValueException",
        "default user can't be deleted."),
    )

    # Effect-absent: the rejected delete left the default user exactly as it was.
    still_default = _describe_user(ec, "default")
    assert still_default is not None, "default user disappeared after a rejected DeleteUser"
    assert still_default["Status"] == "active", still_default
    assert still_default["UserName"] == "default", still_default


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
