"""user-password-punctuation-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-password-punctuation-accepted"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Passwords containing @, /, comma, double quote, space or backslash each create an active
    one-password user.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    for i, ch in enumerate(["@", "/", ",", '"', " ", "\\"]):
        name = f"{base}-c{i}"
        password = f"Sim2realPassword{ch}x"
        m.create_user(UserName=name, AccessString="on ~* +@all",
                      AuthenticationMode={"Type": "password", "Passwords": [password]})
        ctx.on_cleanup(lambda n=name: _drop_user(m, n))
        user = _wait_user_active(m, name)
        assert user["Authentication"] == {"Type": "password", "PasswordCount": 1}, (
            f"password with {ch!r}: authentication {user['Authentication']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
