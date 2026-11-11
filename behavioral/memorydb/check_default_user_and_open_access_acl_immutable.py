"""default-user-and-open-access-acl-immutable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-user-and-open-access-acl-immutable"
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
    """The default user and the open-access ACL refuse update, delete and re-create, and read back
    exactly as they read before; a new empty ACL created beside them settles active and empty.
    """
    m = ctx.client("memorydb")
    acl_name = ctx.unique_name("sim2real-mdb-") + "-acl"
    pw = {"Type": "password", "Passwords": ["Sim2realPassword-1"]}
    refusals = [
        (lambda: m.update_user(UserName="default", AccessString="off -@all"),
         "InvalidParameterValueException", "default user can't be modified."),
        (lambda: m.update_user(UserName="default", AuthenticationMode=pw),
         "InvalidParameterValueException", "default user can't be modified."),
        (lambda: m.delete_user(UserName="default"),
         "InvalidParameterValueException", "default user can't be deleted."),
        (lambda: m.create_user(UserName="default", AccessString="on ~* +@all", AuthenticationMode=pw),
         "UserAlreadyExistsFault", "User default already exists."),
        (lambda: m.update_acl(ACLName="open-access", UserNamesToRemove=["default"]),
         "InvalidParameterValueException", "open-access ACL can't be modified."),
        (lambda: m.delete_acl(ACLName="open-access"),
         "InvalidParameterValueException", "open-access ACL can't be deleted."),
        (lambda: m.create_acl(ACLName="open-access"),
         "ACLAlreadyExistsFault", "ACL open-access already exists. Please retry with another name."),
    ]
    default_before = m.describe_users(UserName="default")["Users"][0]
    open_access_before = m.describe_acls(ACLName="open-access")["ACLs"][0]
    assert open_access_before["Name"] == "open-access", f"open-access read as {open_access_before!r}"
    for i, (fn, want_code, want_msg) in enumerate(refusals):
        code, msg = _error(fn)
        assert code == want_code, f"refusal {i}: expected {want_code}, got {code}: {msg!r}"
        assert msg == want_msg, f"refusal {i}: message was {msg!r}"

    default_after = m.describe_users(UserName="default")["Users"][0]
    assert default_after == default_before, f"the default user changed: {default_before!r} -> {default_after!r}"
    open_access_after = m.describe_acls(ACLName="open-access")["ACLs"][0]
    assert open_access_after == open_access_before, (
        f"open-access changed: {open_access_before!r} -> {open_access_after!r}"
    )

    m.create_acl(ACLName=acl_name)
    ctx.on_cleanup(lambda: _drop_acl(m, acl_name))
    acl = _wait_acl_active(m, acl_name)
    assert (acl["UserNames"], acl["Clusters"]) == ([], []), f"an empty ACL was created as {acl!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
