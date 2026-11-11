"""user-password-rules-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-password-rules-rejected"
GROUP = 'users'
SERVICES = ['memorydb']

_WAIT_TIMEOUT_S = 600


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_when_settled(fn, not_found: str, busy: str) -> None:
    """Delete once the resource leaves a transitional state; a not-found means already gone."""
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == not_found:
                return
            if code != busy or time.monotonic() > deadline:
                raise
        time.sleep(3)


def _wait_user_active(m, name: str) -> dict:
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        user = m.describe_users(UserName=name)["Users"][0]
        if user["Status"] == "active":
            return user
        assert time.monotonic() < deadline, f"user {name!r} stuck in status {user['Status']!r}"
        time.sleep(3)


def _wait_acl_active(m, name: str) -> dict:
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        acl = m.describe_acls(ACLName=name)["ACLs"][0]
        if acl["Status"] == "active":
            return acl
        assert time.monotonic() < deadline, f"ACL {name!r} stuck in status {acl['Status']!r}"
        time.sleep(3)


def _drop_user(m, name: str) -> None:
    _delete_when_settled(lambda: m.delete_user(UserName=name), "UserNotFoundFault", "InvalidUserStateFault")


def _drop_acl(m, name: str) -> None:
    _delete_when_settled(lambda: m.delete_acl(ACLName=name), "ACLNotFoundFault", "InvalidACLStateFault")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUser refuses a password outside 16-128 characters, a password on an IAM user and a
    password user without one, and none of the refusals leaves a user behind.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    cases = [
        ("short", {"Type": "password", "Passwords": ["A" * 15]},
         "InvalidParameterValueException", "Passwords length must be between 16-128 characters."),
        ("long", {"Type": "password", "Passwords": ["A" * 129]},
         "InvalidParameterValueException", "Passwords length must be between 16-128 characters."),
        ("iampw", {"Type": "iam", "Passwords": ["A" * 20]},
         "InvalidParameterCombinationException", "Password field is not allowed with authentication type: iam"),
        ("nopw", {"Type": "password"},
         "InvalidParameterCombinationException",
         "A user with Authentication Mode: password, must have at least one password"),
    ]
    for suffix, mode, want_code, want_msg in cases:
        name = f"{base}-{suffix}"
        ctx.on_cleanup(lambda n=name: _drop_user(m, n))
        code, msg = _error(lambda n=name, a=mode: m.create_user(
            UserName=n, AccessString="on ~* +@all", AuthenticationMode=a))
        assert code == want_code, f"{suffix}: expected {want_code}, got {code}: {msg!r}"
        assert msg == want_msg, f"{suffix}: message was {msg!r}"
        code, msg = _error(lambda n=name: m.describe_users(UserName=n))
        assert code == "UserNotFoundFault", f"{suffix}: refused user is readable, or the read gave {code}"
        assert msg == f"User {name} not found.", f"{suffix}: not-found message was {msg!r}"

    for suffix, length in (("min", 16), ("max", 128)):
        name = f"{base}-{suffix}"
        user = m.create_user(UserName=name, AccessString="on ~* +@all",
                             AuthenticationMode={"Type": "password", "Passwords": ["B" * length]})["User"]
        ctx.on_cleanup(lambda n=name: _drop_user(m, n))
        assert user["Name"] == name, f"boundary user created as {user['Name']!r}"
        assert user["Authentication"] == {"Type": "password", "PasswordCount": 1}, (
            f"a {length}-character password produced {user['Authentication']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
