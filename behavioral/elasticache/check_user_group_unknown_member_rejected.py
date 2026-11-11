"""user-group-unknown-member-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, got = _error(fn, expected[0])
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code}"
    assert got == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {got!r}"
    return code

def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _describe_user_group(ec, group_id):
    return _describe_one(ec.describe_user_groups, "UserGroups", "UserGroupId", group_id)

# budget.cleanup_timeout for behavioral/elasticache, one deadline shared by both teardowns.
_TEARDOWN_RETRY_S = 1800.0


def _delete_retrying(fn, gone, busy, shared):
    """Teardown: done on success or a `gone` code; retry the `busy` state refusal (the group is
    still creating, or the user is still held by a deleting group) every 2 s to the cleanup
    deadline; raise everything else."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code != busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _delete_user(ec, user_id, shared):
    _delete_retrying(lambda: ec.delete_user(UserId=user_id),
                     ("ServiceLinkedRoleNotFoundFault", "UserNotFound"), "InvalidUserState", shared)

def _delete_user_group(ec, group_id, shared):
    _delete_retrying(lambda: ec.delete_user_group(UserGroupId=group_id),
                     ("ServiceLinkedRoleNotFoundFault", "UserGroupNotFound"), "InvalidUserGroupState", shared)

CHECK = "user-group-unknown-member-rejected"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserGroup naming a user id that does not exist is refused with UserNotFound "User <id> not found." and
    creates no group; once that user is created, the identical call creates a group that lists it."""
    ec = ctx.client("elasticache")
    group_id = ctx.unique_name("sim2real-behav-ecug-defuser-")
    ghost_id = ctx.unique_name("sim2real-behav-ecu-ghost-")

    def _create_group():
        return ec.create_user_group(UserGroupId=group_id, Engine="redis", UserIds=["default", ghost_id])

    _assert_error(_create_group, ("UserNotFoundFault", f"User {ghost_id} not found."))
    assert _describe_user_group(ec, group_id) is None

    # Restore: the referenced user now exists, so the identical call must succeed.
    ec.create_user(
        UserId=ghost_id, UserName=ghost_id, Engine="redis",
        AccessString="on ~* +@all", NoPasswordRequired=True,
    )
    teardown_deadline: dict = {}
    ctx.on_cleanup(lambda: _delete_user(ec, ghost_id, teardown_deadline))

    _create_group()
    ctx.on_cleanup(lambda: _delete_user_group(ec, group_id, teardown_deadline))
    restored = _describe_user_group(ec, group_id)
    assert restored is not None, "identical CreateUserGroup call failed after the referenced user was created"
    assert ghost_id in restored["UserIds"], f"expected {ghost_id} in restored group, got {restored['UserIds']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
