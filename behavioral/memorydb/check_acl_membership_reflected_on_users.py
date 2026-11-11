"""acl-membership-reflected-on-users."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acl-membership-reflected-on-users"
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
    """Adding and removing ACL members settles into the ACL's UserNames, each user's ACLNames and the ACL's
    MinimumEngineVersion, which an IAM member raises to 7.0 and its removal restores to 6.2."""
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    upw, uiam, acl_name = base + "-pw", base + "-iam", base + "-acl"
    m.create_user(UserName=upw, AccessString="on ~* +@all",
                  AuthenticationMode={"Type": "password", "Passwords": ["Sim2realPassword-1"]})
    ctx.on_cleanup(lambda: _drop_user(m, upw))
    m.create_user(UserName=uiam, AccessString="on ~* +@all", AuthenticationMode={"Type": "iam"})
    ctx.on_cleanup(lambda: _drop_user(m, uiam))

    created = m.create_acl(ACLName=acl_name, UserNames=[upw], Tags=[{"Key": "sim2real", "Value": CHECK}])["ACL"]
    ctx.on_cleanup(lambda: _drop_acl(m, acl_name))
    assert created["UserNames"] == [upw], f"CreateACL echoed members {created['UserNames']!r}"
    acl = _wait_acl_active(m, acl_name)
    assert acl["UserNames"] == [upw], f"settled ACL members {acl['UserNames']!r}"
    assert acl["MinimumEngineVersion"] == "6.2", f"password-only ACL MEV {acl['MinimumEngineVersion']!r}"
    assert "PendingChanges" not in acl, f"settled ACL still reports pending changes {acl.get('PendingChanges')!r}"
    assert _wait_user_active(m, upw)["ACLNames"] == [acl_name], "member user does not list the ACL"

    upd = m.update_acl(ACLName=acl_name, UserNamesToAdd=[uiam])["ACL"]
    assert upd["PendingChanges"] == {"UserNamesToAdd": [uiam]}, f"pending changes {upd.get('PendingChanges')!r}"
    acl = _wait_acl_active(m, acl_name)
    assert sorted(acl["UserNames"]) == sorted([upw, uiam]), f"after add, members {acl['UserNames']!r}"
    assert acl["MinimumEngineVersion"] == "7.0", f"ACL with an IAM member has MEV {acl['MinimumEngineVersion']!r}"
    assert _wait_user_active(m, uiam)["ACLNames"] == [acl_name], "added IAM user does not list the ACL"

    m.update_acl(ACLName=acl_name, UserNamesToRemove=[uiam])
    acl = _wait_acl_active(m, acl_name)
    assert acl["UserNames"] == [upw], f"after removing the IAM user, members {acl['UserNames']!r}"
    assert acl["MinimumEngineVersion"] == "6.2", f"MEV after removing the IAM member {acl['MinimumEngineVersion']!r}"
    assert _wait_user_active(m, uiam)["ACLNames"] == [], "removed user still lists the ACL"
    assert _wait_user_active(m, upw)["ACLNames"] == [acl_name], "remaining member lost the ACL"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
