"""thing-group-hierarchy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-group-hierarchy"
GROUP = 'thing-group'
SERVICES = ['iot']


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Nested thing groups: child reports its parent, is listed under it, and the parent cannot
    be deleted while the child still exists."""
    iot = ctx.client("iot")
    parent = ctx.unique_name("sim2real-behav-group-parent-")
    child = ctx.unique_name("sim2real-behav-group-child-")
    iot.create_thing_group(thingGroupName=parent)
    ctx.on_cleanup(lambda _n=parent: iot.delete_thing_group(thingGroupName=_n))
    iot.create_thing_group(thingGroupName=child, parentGroupName=parent)
    ctx.on_cleanup(lambda _n=child: iot.delete_thing_group(thingGroupName=_n))

    desc = iot.describe_thing_group(thingGroupName=child)
    actual_parent = desc["thingGroupMetadata"]["parentGroupName"]
    assert actual_parent == parent, (
        f"expected child {child!r}'s parentGroupName to be {parent!r}, got {actual_parent!r}"
    )

    children = _eventually(
        lambda: iot.list_thing_groups(parentGroup=parent).get("thingGroups", []),
        lambda gs: any(g["groupName"] == child for g in gs),
        timeout_s=60,
        interval_s=2,
    )
    child_names = {g["groupName"] for g in children}
    assert child in child_names, (
        f"expected {child!r} listed under parent {parent!r} via ListThingGroups, got {child_names!r}"
    )

    # The hierarchy is enforced on delete too, not just on read: a parent with a live child cannot
    # be removed.
    blocked_code, blocked_code_message = _error(lambda: iot.delete_thing_group(thingGroupName=parent))
    assert blocked_code == "InvalidRequestException", (
        f"expected DeleteThingGroup on parent {parent!r} with a live child to be refused with "
        f"InvalidRequestException, got {blocked_code!r}"
    )
    assert blocked_code_message == f"Cannot delete thing group : {parent} when there are still child groups attached to it", (
        f"expected the exact {blocked_code} message, got {blocked_code_message!r}"
    )
    still_there = iot.describe_thing_group(thingGroupName=parent)
    assert still_there.get("thingGroupName") == parent, (
        f"parent {parent!r} must still exist after the refused delete, got {still_there!r}"
    )

    iot.delete_thing_group(thingGroupName=child)
    child_gone, child_gone_message = _error(lambda: iot.describe_thing_group(thingGroupName=child))
    assert child_gone == "ResourceNotFoundException", (
        f"expected deleted child {child!r} to be gone, DescribeThingGroup gave {child_gone!r}"
    )
    assert child_gone_message == f"ThingGroup {ctx.account}:{child} not found.", (
        f"expected the exact {child_gone} message, got {child_gone_message!r}"
    )

    # The "still has children" state above is enforced from the same registry that
    # DeleteThingGroup(child) just wrote to asynchronously, so the parent delete may
    # transiently see the stale attachment for a moment after the child is gone.
    def _delete_parent_once():
        iot.delete_thing_group(thingGroupName=parent)
        return True

    _eventually(_delete_parent_once, lambda ok: ok, timeout_s=30, interval_s=2)
    parent_gone, parent_gone_message = _error(lambda: iot.describe_thing_group(thingGroupName=parent))
    assert parent_gone == "ResourceNotFoundException", (
        f"expected parent {parent!r} to be deletable once its child is gone, "
        f"DescribeThingGroup gave {parent_gone!r}"
    )
    assert parent_gone_message == f"ThingGroup {ctx.account}:{parent} not found.", (
        f"expected the exact {parent_gone} message, got {parent_gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
