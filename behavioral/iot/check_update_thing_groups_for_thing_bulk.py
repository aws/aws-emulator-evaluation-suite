"""update-thing-groups-for-thing-bulk."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-thing-groups-for-thing-bulk"
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

def _delete_thing_group(iot, name):
    """Best-effort teardown: delete a thing group."""
    iot.delete_thing_group(thingGroupName=name)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateThingGroupsForThing applies adds and removes atomically in one call."""
    iot = ctx.client("iot")
    g1 = ctx.unique_name("sim2real-behav-tg-bulk1-")
    g2 = ctx.unique_name("sim2real-behav-tg-bulk2-")
    g3 = ctx.unique_name("sim2real-behav-tg-bulk3-")
    thing = ctx.unique_name("sim2real-behav-thing-bulk-")
    for g in (g1, g2, g3):
        iot.create_thing_group(
            thingGroupName=g,
            tags=[{"Key": "sim2real", "Value": "update-thing-groups-for-thing-bulk"}],
        )
        ctx.on_cleanup(lambda _n=g: _delete_thing_group(iot, _n))
    # IoT Things are not a taggable resource type (TagResource rejects a thing ARN with
    # InvalidRequestException), unlike thing groups above -- confirmed against real AWS.
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    def groups_for_thing():
        return [
            g["groupName"]
            for g in iot.list_thing_groups_for_thing(thingName=thing).get("thingGroups", [])
        ]

    iot.update_thing_groups_for_thing(thingName=thing, thingGroupsToAdd=[g1, g2])
    both = _eventually(groups_for_thing, lambda gs: g1 in gs and g2 in gs, timeout_s=30, interval_s=2.0)
    assert g1 in both and g2 in both, both

    # One call that simultaneously adds g3 and removes g1, leaving g2 untouched:
    # this is the "atomically in one call" claim, and it is only tested if add and
    # remove are in the SAME request rather than two separate ones.
    iot.update_thing_groups_for_thing(thingName=thing, thingGroupsToAdd=[g3], thingGroupsToRemove=[g1])
    after = _eventually(
        groups_for_thing,
        lambda gs: g1 not in gs and g3 in gs,
        timeout_s=30,
        interval_s=2.0,
    )
    assert g1 not in after, f"g1 must be removed by the combined call, got {after}"
    assert g3 in after, f"g3 must be added by the combined call, got {after}"
    assert g2 in after, f"g2 membership must survive the combined add/remove, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
