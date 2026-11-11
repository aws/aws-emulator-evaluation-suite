"""resource-names-fold-to-lowercase."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-names-fold-to-lowercase"
GROUP = 'naming'
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Mixed-case user, ACL and parameter group names are stored lowercased, read back by the
    lowercase name, and collide with a later lowercase create; a family name folds too.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    mixed = base + "-MiXed"
    lower = mixed.lower()
    pw = {"Type": "password", "Passwords": ["Sim2realPassword-1"]}

    user = m.create_user(UserName=mixed, AccessString="on ~* +@all", AuthenticationMode=pw)["User"]
    ctx.on_cleanup(lambda: _drop_user(m, lower))
    assert user["Name"] == lower, f"user stored as {user['Name']!r}, expected {lower!r}"
    assert m.describe_users(UserName=lower)["Users"][0]["Name"] == lower, "lowercase read missed the user"
    code, msg = _error(lambda: m.create_user(UserName=lower, AccessString="on ~* +@all", AuthenticationMode=pw))
    assert code == "UserAlreadyExistsFault", f"lowercase re-create gave {code}: {msg!r}"
    assert msg == f"User {lower} already exists.", f"message was {msg!r}"

    acl = m.create_acl(ACLName=mixed)["ACL"]
    ctx.on_cleanup(lambda: _drop_acl(m, lower))
    assert acl["Name"] == lower, f"ACL stored as {acl['Name']!r}, expected {lower!r}"
    assert m.describe_acls(ACLName=lower)["ACLs"][0]["Name"] == lower, "lowercase read missed the ACL"
    code, msg = _error(lambda: m.create_acl(ACLName=lower))
    assert code == "ACLAlreadyExistsFault", f"lowercase ACL re-create gave {code}: {msg!r}"
    assert msg == f"ACL {lower} already exists. Please retry with another name.", f"message was {msg!r}"

    pg = m.create_parameter_group(ParameterGroupName=mixed, Family="MEMORYDB_VALKEY7")["ParameterGroup"]
    ctx.on_cleanup(lambda: _drop_pg(m, lower))
    assert pg["Name"] == lower, f"parameter group stored as {pg['Name']!r}, expected {lower!r}"
    assert pg["Family"] == "memorydb_valkey7", f"family stored as {pg['Family']!r}"
    got = m.describe_parameter_groups(ParameterGroupName=lower)["ParameterGroups"][0]
    assert (got["Name"], got["Family"]) == (lower, "memorydb_valkey7"), f"lowercase read returned {got!r}"
    code, msg = _error(lambda: m.create_parameter_group(ParameterGroupName=lower, Family="memorydb_valkey7"))
    assert code == "ParameterGroupAlreadyExistsFault", f"lowercase group re-create gave {code}: {msg!r}"
    assert msg == "Parameter Group already exists.", f"message was {msg!r}"


def _drop_pg(m, name: str) -> None:
    try:
        m.delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterGroupNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
