"""user-group-delete-while-creating-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-group-delete-while-creating-rejected"
GROUP = "state-machine"
SERVICES = ["elasticache"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh user groups tried before the check gives up on observing the creating window.
_ATTEMPTS = 5
#: Bound on each wait for a group to settle; the runner's remaining time bounds it further.
_SETTLE_TIMEOUT_S = 600.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserGroup on a user group still creating is refused with InvalidUserGroupState and its
    exact message, and the refused delete leaves the group to settle active."""
    ec = ctx.client("elasticache")
    tried = []
    group = None
    for _ in range(_ATTEMPTS):
        candidate = ctx.unique_name("sim2real-ec-ugdel-")
        created = ec.create_user_group(UserGroupId=candidate, Engine="redis", UserIds=["default"],
                                       Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda g=candidate: _drop(ec, g))
        assert created["Status"] == "creating", (
            f"CreateUserGroup answered Status {created['Status']!r}, expected 'creating'"
        )
        before = _status(ec, candidate)
        if before != "creating":
            tried.append(f"{candidate}: read {before!r} before the delete")
            continue
        code, message = _outcome(lambda: ec.delete_user_group(UserGroupId=candidate))
        expected = (f"User group {candidate} has status creating. Only active or create-failed user "
                    "groups can be deleted.")
        if (code, message) == ("InvalidUserGroupState", expected):
            group = candidate
            break
        after = _status(ec, candidate)
        assert after != "creating", (
            f"DeleteUserGroup on a creating group answered {code!r} {message!r}; expected "
            f"InvalidUserGroupState {expected!r}"
        )
        assert code == _ACCEPTED, f"DeleteUserGroup answered {code!r} {message!r} once the group was {after!r}"
        tried.append(f"{candidate}: delete accepted after the group left creating ({after!r})")
    assert group, f"DeleteUserGroup was never refused while creating in {_ATTEMPTS} groups: {tried!r}"

    left = ctx.time_left()
    timeout = _SETTLE_TIMEOUT_S if left is None else max(1.0, min(_SETTLE_TIMEOUT_S, left - min(60.0, left / 4)))
    settled = _settle(ec, group, timeout)
    assert settled == "active", f"after the refused delete the group settled {settled!r}, expected 'active'"


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _status(ec, group: str) -> str | None:
    try:
        return ec.describe_user_groups(UserGroupId=group)["UserGroups"][0]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UserGroupNotFound":
            return None
        raise


def _settle(ec, group: str, timeout: float = _SETTLE_TIMEOUT_S) -> str | None:
    """Poll until the group leaves creating (or is gone); returns the status reached."""
    deadline = time.monotonic() + timeout
    status = _status(ec, group)
    while status == "creating":
        if time.monotonic() >= deadline:
            raise AssertionError(f"user group {group} still creating after {timeout:.0f}s")
        time.sleep(3)
        status = _status(ec, group)
    return status


def _drop(ec, group: str) -> None:
    """Delete the group once it leaves creating; already gone or deleting counts as deleted."""
    status = _settle(ec, group)
    if status in (None, "deleting"):
        return
    try:
        ec.delete_user_group(UserGroupId=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UserGroupNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
