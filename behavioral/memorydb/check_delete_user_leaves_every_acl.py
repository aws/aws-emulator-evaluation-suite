"""delete-user-leaves-every-acl."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-leaves-every-acl"
GROUP = 'acls'
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a user that belongs to two ACLs removes it from both, leaves the other member in
    place and leaves both ACLs active.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    gone, kept, acl_a, acl_b = base + "-gone", base + "-kept", base + "-a", base + "-b"
    pw = {"Type": "password", "Passwords": ["Sim2realPassword-1"]}
    for u in (gone, kept):
        m.create_user(UserName=u, AccessString="on ~* +@all", AuthenticationMode=pw)
        ctx.on_cleanup(lambda n=u: _drop_user(m, n))
    m.create_acl(ACLName=acl_a, UserNames=[gone, kept])
    ctx.on_cleanup(lambda: _drop_acl(m, acl_a))
    m.create_acl(ACLName=acl_b, UserNames=[gone])
    ctx.on_cleanup(lambda: _drop_acl(m, acl_b))
    _wait_acl_active(m, acl_a)
    _wait_acl_active(m, acl_b)
    member = _wait_user_active(m, gone)
    assert sorted(member["ACLNames"]) == sorted([acl_a, acl_b]), f"user lists ACLs {member['ACLNames']!r}"

    deleted = m.delete_user(UserName=gone)["User"]
    assert deleted["Name"] == gone, f"DeleteUser returned {deleted['Name']!r}"
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        code, msg = _probe_user(m, gone)
        if code == "UserNotFoundFault":
            break
        assert time.monotonic() < deadline, f"deleted user never disappeared; last read {code!r}"
        time.sleep(3)
    assert msg == f"User {gone} not found.", f"not-found message was {msg!r}"

    a = _wait_acl_active(m, acl_a)
    while gone in a["UserNames"]:
        assert time.monotonic() < deadline, f"ACL a still lists the deleted user: {a['UserNames']!r}"
        time.sleep(3)
        a = _wait_acl_active(m, acl_a)
    b = _wait_acl_active(m, acl_b)
    while gone in b["UserNames"]:
        assert time.monotonic() < deadline, f"ACL b still lists the deleted user: {b['UserNames']!r}"
        time.sleep(3)
        b = _wait_acl_active(m, acl_b)
    assert a["UserNames"] == [kept], f"ACL a members after the delete {a['UserNames']!r}"
    assert b["UserNames"] == [], f"ACL b members after the delete {b['UserNames']!r}"
    assert _wait_user_active(m, kept)["ACLNames"] == [acl_a], "the surviving member lost its ACL"


def _probe_user(m, name: str):
    try:
        m.describe_users(UserName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "present", None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
