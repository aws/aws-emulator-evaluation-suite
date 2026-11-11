"""add-remove-thing-from-group."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "add-remove-thing-from-group"
GROUP = 'thing-group'
SERVICES = ['iot']

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
    """Adding/removing a thing to/from a thing group is reflected in membership listings."""
    iot = ctx.client("iot")
    group = ctx.unique_name("sim2real-behav-group-")
    thing = ctx.unique_name("sim2real-behav-thing-grp-member-")
    iot.create_thing_group(thingGroupName=group, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda _n=group: iot.delete_thing_group(thingGroupName=_n))
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    iot.add_thing_to_thing_group(thingGroupName=group, thingName=thing)
    members = _eventually(
        lambda: iot.list_things_in_thing_group(thingGroupName=group).get("things", []),
        lambda ms: thing in ms,
        timeout_s=90,
        interval_s=3,
    )
    assert thing in members, f"expected {thing!r} in group membership, got {members!r}"

    groups_for_thing = _eventually(
        lambda: iot.list_thing_groups_for_thing(thingName=thing).get("thingGroups", []),
        lambda gs: any(g["groupName"] == group for g in gs),
        timeout_s=90,
        interval_s=3,
    )
    assert any(g["groupName"] == group for g in groups_for_thing), (
        f"expected {group!r} in {thing!r}'s groups, got {groups_for_thing!r}"
    )

    iot.remove_thing_from_thing_group(thingGroupName=group, thingName=thing)
    members_after = _eventually(
        lambda: iot.list_things_in_thing_group(thingGroupName=group).get("things", []),
        lambda ms: thing not in ms,
        timeout_s=90,
        interval_s=3,
    )
    assert thing not in members_after, (
        f"expected {thing!r} removed from group membership, still present in {members_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
