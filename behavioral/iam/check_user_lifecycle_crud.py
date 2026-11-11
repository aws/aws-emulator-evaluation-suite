"""user-lifecycle-crud."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-lifecycle-crud"
GROUP = 'user_lifecycle'
SERVICES = ['iam']

_MSG_UPDATE_MISSING = "The user with name {name} cannot be found."


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(fn, predicate, timeout_s=10.0, interval_s=0.5, desc=""):
    deadline = time.monotonic() + timeout_s
    while True:
        value = fn()
        if predicate(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last seen: {value}")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """State machine: CreateUser -> active (GetUser/ListUsers reflect it) -> UpdateUser (rename)
    -> DeleteUser -> absent (GetUser 404, ListUsers gone, a mutation on the dead id fails)."""
    iam = ctx.client("iam")
    old_name = ctx.unique_name("sim2real-behav-user-")
    new_name = ctx.unique_name("sim2real-behav-user-renamed-")
    current_name = {"name": old_name}
    # A path of the check's own scopes ListUsers to this user alone, however many users share
    # the account.
    path = f"/sim2real/{ctx.unique_name('lifecycle-')}/"

    def _cleanup():
        try:
            iam.delete_user(UserName=current_name["name"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    created = iam.create_user(UserName=old_name, Path=path)
    user_id = created["User"]["UserId"]
    assert created["User"]["UserName"] == old_name, (
        f"CreateUser echoed UserName {created['User']['UserName']!r}, expected {old_name!r}"
    )

    got = iam.get_user(UserName=old_name)
    assert got["User"]["UserId"] == user_id, (
        f"GetUser returned UserId {got['User']['UserId']!r}, expected {user_id!r}"
    )

    names = _poll_until(
        lambda: [u["UserName"] for u in iam.list_users(PathPrefix=path)["Users"]],
        lambda ns: old_name in ns,
        desc=f"{old_name} to appear in ListUsers",
    )
    assert old_name in names, f"newly created user missing from ListUsers: {names}"

    iam.update_user(UserName=old_name, NewUserName=new_name)
    current_name["name"] = new_name
    err = _client_error(lambda: iam.get_user(UserName=old_name))
    assert err.get("Code") == "NoSuchEntity", f"expected NoSuchEntity for old name, got {err!r}"
    expected_msg = f"The user with name {old_name} cannot be found."
    assert err.get("Message") == expected_msg, (err.get("Message"), expected_msg)
    got2 = iam.get_user(UserName=new_name)
    assert got2["User"]["UserId"] == user_id, (
        f"GetUser after rename returned UserId {got2['User']['UserId']!r}, expected {user_id!r}"
    )

    iam.delete_user(UserName=new_name)
    err2 = _client_error(lambda: iam.get_user(UserName=new_name))
    assert err2.get("Code") == "NoSuchEntity", f"expected NoSuchEntity after delete, got {err2!r}"
    expected_msg2 = f"The user with name {new_name} cannot be found."
    assert err2.get("Message") == expected_msg2, (err2.get("Message"), expected_msg2)

    mutation = _client_error(lambda: iam.update_user(UserName=new_name, NewUserName=old_name))
    assert mutation.get("Code") == "NoSuchEntity", (
        f"expected a mutation on the deleted user to fail NoSuchEntity, got {mutation!r}"
    )
    expected_mutation_msg = _MSG_UPDATE_MISSING.format(name=new_name)
    assert mutation.get("Message") == expected_mutation_msg, (
        mutation.get("Message"),
        expected_mutation_msg,
    )

    names_after = _poll_until(
        lambda: [u["UserName"] for u in iam.list_users(PathPrefix=path)["Users"]],
        lambda ns: new_name not in ns,
        desc=f"{new_name} to disappear from ListUsers",
    )
    assert new_name not in names_after, "deleted user still present in ListUsers"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
