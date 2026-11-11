"""group-lifecycle-crud."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "group-lifecycle-crud"
GROUP = 'groups'
SERVICES = ['iam']


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_no_such_entity(fn):
    """Teardown-only: the body deletes the group itself, so tolerate it already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, *, timeout_s=20.0, interval_s=1.5, description="condition"):
    """Bounded retry for ListGroups' list-after-write eventual consistency; raises (never
    returns a stale value) if the deadline passes without the condition holding."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _group_names(iam, path_prefix):
    return [g["GroupName"] for g in iam.list_groups(PathPrefix=path_prefix)["Groups"]]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """State machine: CreateGroup -> active (GetGroup/ListGroups reflect it) -> UpdateGroup
    (rename) -> DeleteGroup -> absent, and a second delete on the dead id fails too."""
    iam = ctx.client("iam")
    path_prefix = "/sim2real/"
    old_name = ctx.unique_name("sim2real-behav-group-")
    new_name = ctx.unique_name("sim2real-behav-group-renamed-")
    created = iam.create_group(GroupName=old_name, Path=path_prefix)
    group_id = created["Group"]["GroupId"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_group(GroupName=new_name)))

    got = iam.get_group(GroupName=old_name)
    assert got["Group"]["GroupId"] == group_id, (
        f"GetGroup returned GroupId {got['Group']['GroupId']!r}, expected {group_id!r}"
    )

    _poll_until(
        lambda: _group_names(iam, path_prefix),
        lambda names: old_name in names,
        description=f"ListGroups reflecting newly created group {old_name!r}",
    )

    iam.update_group(GroupName=old_name, NewGroupName=new_name)
    code, message = _error(lambda: iam.get_group(GroupName=old_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for old name, got {code}: {message!r}"
    expected = f"The group with name {old_name} cannot be found."
    assert message == expected, f"GetGroup(old name) message: expected {expected!r}, got {message!r}"
    got2 = iam.get_group(GroupName=new_name)
    assert got2["Group"]["GroupId"] == group_id, (
        f"GetGroup after rename returned GroupId {got2['Group']['GroupId']!r}, expected {group_id!r}"
    )

    iam.delete_group(GroupName=new_name)
    code2, message2 = _error(lambda: iam.get_group(GroupName=new_name))
    assert code2 == "NoSuchEntity", f"expected NoSuchEntity for deleted group, got {code2}: {message2!r}"
    expected2 = f"The group with name {new_name} cannot be found."
    assert message2 == expected2, (
        f"GetGroup(deleted) message: expected {expected2!r}, got {message2!r}"
    )
    code3, message3 = _error(lambda: iam.delete_group(GroupName=new_name))
    assert code3 == "NoSuchEntity", (
        f"expected a second delete on the dead id to fail too, got {code3}: {message3!r}"
    )
    expected3 = f"The group with name {new_name} cannot be found."
    assert message3 == expected3, (
        f"DeleteGroup(deleted) message: expected {expected3!r}, got {message3!r}"
    )

    _poll_until(
        lambda: _group_names(iam, path_prefix),
        lambda names: new_name not in names,
        description=f"ListGroups no longer showing deleted group {new_name!r}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
