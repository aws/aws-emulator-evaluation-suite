"""user-password-count-and-auth-mode-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-password-count-and-auth-mode-transitions"
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A user moves between one password, two passwords, IAM and back, and each settled state
    reports the right password count and minimum engine version; a third password is refused
    and leaves the count at two.
    """
    m = ctx.client("memorydb")
    name = ctx.unique_name("sim2real-mdb-")
    pw1, pw2, pw3 = "Sim2realPassword-1", "Sim2realPassword-2", "Sim2realPassword-3"

    created = m.create_user(
        UserName=name, AccessString="on ~* +@all",
        AuthenticationMode={"Type": "password", "Passwords": [pw1]},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["User"]
    ctx.on_cleanup(lambda: _drop_user(m, name))
    assert created["Authentication"] == {"Type": "password", "PasswordCount": 1}, (
        f"a one-password user reported {created['Authentication']!r}"
    )
    assert created["AccessString"] == "on ~* resetchannels +@all", (
        f"access string was not normalised: {created['AccessString']!r}"
    )
    assert created["MinimumEngineVersion"] == "6.2", f"password user MEV {created['MinimumEngineVersion']!r}"
    _wait_user_active(m, name)

    m.update_user(UserName=name, AuthenticationMode={"Type": "password", "Passwords": [pw1, pw2]})
    two = _wait_user_active(m, name)
    assert two["Authentication"] == {"Type": "password", "PasswordCount": 2}, (
        f"after setting two passwords the user reported {two['Authentication']!r}"
    )

    code, msg = _error(lambda: m.update_user(
        UserName=name, AuthenticationMode={"Type": "password", "Passwords": [pw1, pw2, pw3]}))
    assert code == "InvalidParameterValueException", f"a third password gave {code}: {msg!r}"
    assert msg == "Maximum number of passwords allowed in this service is 2.", f"message was {msg!r}"
    still = m.describe_users(UserName=name)["Users"][0]
    assert still["Status"] == "active", f"a refused update moved the user to {still['Status']!r}"
    assert still["Authentication"] == {"Type": "password", "PasswordCount": 2}, (
        f"a refused third password changed the user to {still['Authentication']!r}"
    )

    m.update_user(UserName=name, AuthenticationMode={"Type": "iam"})
    iam = _wait_user_active(m, name)
    assert iam["Authentication"] == {"Type": "iam"}, f"an IAM user reported {iam['Authentication']!r}"
    assert iam["MinimumEngineVersion"] == "7.0", f"IAM user MEV {iam['MinimumEngineVersion']!r}, expected '7.0'"
    assert iam["AccessString"] == "on ~* resetchannels +@all", f"auth change touched access {iam['AccessString']!r}"

    m.update_user(UserName=name, AuthenticationMode={"Type": "password", "Passwords": [pw3]})
    back = _wait_user_active(m, name)
    assert back["Authentication"] == {"Type": "password", "PasswordCount": 1}, (
        f"switching back to one password reported {back['Authentication']!r}"
    )
    assert back["MinimumEngineVersion"] == "6.2", f"password user MEV after IAM {back['MinimumEngineVersion']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
