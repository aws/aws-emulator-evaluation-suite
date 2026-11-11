"""resource-name-rules-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-name-rules-rejected"
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

_PATTERN = ("must begin with a letter; must contain only ASCII letters, digits, and hyphens; "
            "and must not end with a hyphen or contain two consecutive hyphens.")


def _all_user_names(m) -> set:
    return {u["Name"] for page in m.get_paginator("describe_users").paginate() for u in page["Users"]}


def _all_acl_names(m) -> set:
    return {a["Name"] for page in m.get_paginator("describe_acls").paginate() for a in page["ACLs"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """User and ACL names over 40 characters, starting with a digit, holding an underscore or a
    double hyphen are refused and never listed, while a 40-character name is accepted.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")  # 25 characters
    pw = {"Type": "password", "Passwords": ["Sim2realPassword-1"]}

    ok40 = (base + "-" + "a" * 40)[:40]
    created = m.create_user(UserName=ok40, AccessString="on ~* +@all", AuthenticationMode=pw)["User"]
    ctx.on_cleanup(lambda: _drop_user(m, ok40))
    assert created["Name"] == ok40, f"40-character user created as {created['Name']!r}"
    acl40 = m.create_acl(ACLName=ok40)["ACL"]
    ctx.on_cleanup(lambda: _drop_acl(m, ok40))
    assert acl40["Name"] == ok40, f"40-character ACL created as {acl40['Name']!r}"

    too_long = (base + "-" + "b" * 40)[:41]
    bad = {
        "too-long": too_long,
        "digit": "9" + base[1:],
        "underscore": base + "_x",
        "double-hyphen": base + "--x",
    }
    for label, name in bad.items():
        ctx.on_cleanup(lambda n=name: _drop_user_if_valid(m, n))
        code, msg = _error(lambda n=name: m.create_user(UserName=n, AccessString="on ~* +@all",
                                                       AuthenticationMode=pw))
        assert code == "InvalidParameterValueException", f"user {label}: got {code}: {msg!r}"
        want = "User id length must be less than 40." if label == "too-long" else f"User id {_PATTERN}"
        assert msg == want, f"user {label}: message was {msg!r}"
        code, msg = _error(lambda n=name: m.create_acl(ACLName=n))
        assert code == "InvalidParameterValueException", f"ACL {label}: got {code}: {msg!r}"
        want = "ACL name length must be less than 40." if label == "too-long" else f"ACL name {_PATTERN}"
        assert msg == want, f"ACL {label}: message was {msg!r}"

    users, acls = _all_user_names(m), _all_acl_names(m)
    assert ok40 in users and ok40 in acls, "the accepted 40-character user or ACL is not listed"
    for label, name in bad.items():
        assert name not in users, f"refused user ({label}) appears in DescribeUsers"
        assert name not in acls, f"refused ACL ({label}) appears in DescribeACLs"


def _drop_user_if_valid(m, name: str) -> None:
    """Teardown for a refused create: only a name the service accepted can exist."""
    try:
        m.delete_user(UserName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("UserNotFoundFault", "InvalidParameterValueException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
