"""events-record-user-and-acl-lifecycle."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-record-user-and-acl-lifecycle"
GROUP = 'events'
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


def _messages(m, source_type: str, name: str, since) -> list:
    events = []
    for page in m.get_paginator("describe_events").paginate(SourceType=source_type, SourceName=name,
                                                             StartTime=since):
        events += page["Events"]
    for e in events:
        assert (e["SourceType"], e["SourceName"]) == (source_type, name), f"filter leaked event {e!r}"
    dates = [e["Date"] for e in events]
    assert dates == sorted(dates, reverse=True), "events are not newest first"
    return [e["Message"] for e in events]


def _await_messages(m, source_type: str, name: str, since, want: set) -> list:
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        got = _messages(m, source_type, name, since)
        if want <= set(got):
            return got
        assert time.monotonic() < deadline, f"{source_type} events never showed {sorted(want - set(got))!r}"
        time.sleep(5)


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating, modifying and deleting a user, and creating an ACL and adding the user, each
    surface as DescribeEvents entries under the right source type and name, newest first.
    """
    m = ctx.client("memorydb")
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    base = ctx.unique_name("sim2real-mdb-")
    user, acl = base + "-u", base + "-acl"
    m.create_user(UserName=user, AccessString="on ~* +@all",
                  AuthenticationMode={"Type": "password", "Passwords": ["Sim2realPassword-1"]})
    ctx.on_cleanup(lambda: _drop_user(m, user))
    _wait_user_active(m, user)
    m.update_user(UserName=user, AccessString="on ~app:* +@read")
    _wait_user_active(m, user)
    m.create_acl(ACLName=acl)
    ctx.on_cleanup(lambda: _drop_acl(m, acl))
    m.update_acl(ACLName=acl, UserNamesToAdd=[user])
    _wait_acl_active(m, acl)

    _await_messages(m, "acl", acl, since, {
        f"Create ACL {acl} operation completed.",
        f"Add user {user} to ACL {acl} operation completed.",
    })
    m.update_acl(ACLName=acl, UserNamesToRemove=[user])
    _wait_acl_active(m, acl)
    _await_messages(m, "acl", acl, since, {f"Remove user {user} from ACL {acl} operation completed."})

    m.delete_user(UserName=user)
    got = _await_messages(m, "user", user, since, {
        f"Create user {user} operation completed.",
        f"Modify user {user} operation completed.",
        f"Delete user {user} operation completed.",
    })
    assert got[0] == f"Delete user {user} operation completed.", f"newest user event is {got[0]!r}"
    assert got[-1] == f"Create user {user} operation completed.", f"oldest user event is {got[-1]!r}"
    assert _messages(m, "user", user.upper(), since) == [], "an uppercase source name matched the user's events"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
