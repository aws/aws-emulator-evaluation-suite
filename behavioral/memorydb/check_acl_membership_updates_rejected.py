"""acl-membership-updates-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acl-membership-updates-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateACL refuses re-adding a member, removing a non-member, adding the default user, adding an
    unknown user and an empty change, and CreateACL refuses duplicate and unknown members, each with its
    exact code and message; none changes the ACL, and a valid add afterwards lands."""
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    ua, ub, missing, acl_name = base + "-a", base + "-b", base + "-none", base + "-acl"
    pw = {"Type": "password", "Passwords": ["Sim2realPassword-1"]}
    for u in (ua, ub):
        m.create_user(UserName=u, AccessString="on ~* +@all", AuthenticationMode=pw)
        ctx.on_cleanup(lambda n=u: _drop_user(m, n))
    m.create_acl(ACLName=acl_name, UserNames=[ua])
    ctx.on_cleanup(lambda: _drop_acl(m, acl_name))
    _wait_acl_active(m, acl_name)

    refusals = [
        (dict(UserNamesToAdd=[ua]), "InvalidParameterCombinationException", f"{ua} is already a member of {acl_name}."),
        (dict(UserNamesToRemove=[ub]), "InvalidParameterValueException", f"User {ub} is not a member of ACL {acl_name}."),
        (dict(UserNamesToAdd=["default"]), "InvalidParameterValueException", "default user can't be added to another ACL."),
        (dict(UserNamesToAdd=[missing]), "UserNotFoundFault", f"User {missing} not found."),
        (dict(), "InvalidParameterCombinationException", "Please specify the list of user names to be added or removed."),
    ]
    for change, want_code, want_msg in refusals:
        code, msg = _error(lambda c=change: m.update_acl(ACLName=acl_name, **c))
        assert code == want_code, f"UpdateACL {change!r}: expected {want_code}, got {code}: {msg!r}"
        assert msg == want_msg, f"UpdateACL {change!r}: message was {msg!r}"
        acl = m.describe_acls(ACLName=acl_name)["ACLs"][0]
        assert (acl["Status"], acl["UserNames"]) == ("active", [ua]), (
            f"refused UpdateACL {change!r} changed the ACL to {acl['Status']!r} {acl['UserNames']!r}"
        )

    for suffix, members, want_code, want_msg in (
        ("dup", [ua, ua], "InvalidParameterValueException", "Duplicate user name specified."),
        ("unknown", [missing], "UserNotFoundFault", f"User {missing} not found."),
    ):
        name = f"{acl_name}-{suffix}"
        ctx.on_cleanup(lambda n=name: _drop_acl(m, n))
        code, msg = _error(lambda n=name, u=members: m.create_acl(ACLName=n, UserNames=u))
        assert code == want_code, f"CreateACL {suffix}: expected {want_code}, got {code}: {msg!r}"
        assert msg == want_msg, f"CreateACL {suffix}: message was {msg!r}"
        code, msg = _error(lambda n=name: m.describe_acls(ACLName=n))
        assert code == "ACLNotFoundFault", f"refused ACL {suffix} is readable, or the read gave {code}"
        assert msg == f"ACL {name} not found", f"not-found message was {msg!r}"

    m.update_acl(ACLName=acl_name, UserNamesToAdd=[ub])
    acl = _wait_acl_active(m, acl_name)
    assert sorted(acl["UserNames"]) == sorted([ua, ub]), f"valid add after refusals gave {acl['UserNames']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
