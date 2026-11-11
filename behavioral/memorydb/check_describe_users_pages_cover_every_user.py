"""describe-users-pages-cover-every-user."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-users-pages-cover-every-user"
GROUP = 'pagination'
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


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging DescribeUsers and DescribeACLs one item at a time visits every created user and ACL
    exactly once and ends without a token; the user-name filter returns only its user, and
    MaxResults outside 1-50 is refused.
    """
    m = ctx.client("memorydb")
    base = ctx.unique_name("sim2real-mdb-")
    names = [f"{base}-{i}" for i in range(3)]
    for n in names:
        m.create_user(UserName=n, AccessString="on ~* +@all",
                      AuthenticationMode={"Type": "password", "Passwords": ["Sim2realPassword-1"]})
        ctx.on_cleanup(lambda x=n: _drop_user(m, x))
        m.create_acl(ACLName=n)
        ctx.on_cleanup(lambda x=n: _drop_acl(m, x))

    for op, key in (("describe_users", "Users"), ("describe_acls", "ACLs")):
        seen, token, pages = [], None, 0
        while True:
            kwargs = {"MaxResults": 1, **({"NextToken": token} if token else {})}
            page = getattr(m, op)(**kwargs)
            assert len(page[key]) <= 1, f"{op} MaxResults=1 returned {len(page[key])} items"
            seen += [x["Name"] for x in page[key]]
            token = page.get("NextToken")
            pages += 1
            assert pages < 10000, f"{op} pagination never ended"
            if not token:
                break
        # Other checks may create and delete users and ACLs in the account meanwhile, so only this
        # check's own items are held to exactly-once.
        own = [n for n in seen if n in names]
        assert len(own) == len(set(own)), f"{op} pagination repeated a created item"
        missing = [n for n in names if n not in own]
        assert not missing, f"{op} pagination skipped {len(missing)} created item(s)"

        for bad in (0, 51):
            code, msg = _error(lambda o=op, b=bad: getattr(m, o)(MaxResults=b))
            assert code == "InvalidParameterValueException", f"{op} MaxResults={bad} gave {code}: {msg!r}"
            assert msg == "Invalid value for max results. Must be between 1 and 50", f"message was {msg!r}"

    only = m.describe_users(Filters=[{"Name": "user-name", "Values": [names[1]]}])["Users"]
    assert [u["Name"] for u in only] == [names[1]], f"user-name filter returned {[u['Name'] for u in only]!r}"
    code, msg = _error(lambda: m.describe_users(Filters=[{"Name": "UserName", "Values": [names[1]]}]))
    assert (code, msg) == ("InvalidParameterValueException", "Invalid filter name UserName."), (
        f"an unknown filter name gave {code}: {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
