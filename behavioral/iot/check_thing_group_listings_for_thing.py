"""thing-group-listings-for-thing."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "thing-group-listings-for-thing"
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
    """ListThingGroupsForThing reflects membership; UpdateThingGroup mutates properties."""
    iot = ctx.client("iot")
    group = ctx.unique_name("sim2real-behav-tg-list-")
    thing = ctx.unique_name("sim2real-behav-thing-tglist-")
    iot.create_thing_group(
        thingGroupName=group,
        thingGroupProperties={"thingGroupDescription": "before"},
        tags=[{"Key": "sim2real", "Value": "thing-group-listings"}],
    )
    ctx.on_cleanup(lambda _n=group: _delete_thing_group(iot, _n))
    thing_resp = iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    try:
        iot.tag_resource(
            resourceArn=thing_resp["thingArn"],
            tags=[{"Key": "sim2real", "Value": "thing-group-listings"}],
        )
    except Exception:  # noqa: BLE001 - tagging is best-effort, not the assertion under test
        pass

    iot.add_thing_to_thing_group(thingGroupName=group, thingName=thing)
    groups = _eventually(
        lambda: [g["groupName"] for g in iot.list_thing_groups_for_thing(thingName=thing).get("thingGroups", [])],
        lambda gs: group in gs,
        timeout_s=30,
        interval_s=2.0,
    )
    assert group in groups, groups

    iot.update_thing_group(
        thingGroupName=group,
        thingGroupProperties={"thingGroupDescription": "after"},
    )
    desc = iot.describe_thing_group(thingGroupName=group)
    got_desc = desc["thingGroupProperties"]["thingGroupDescription"]
    assert got_desc == "after", f"expected updated description 'after', got {got_desc!r}"

    all_groups = [
        g["groupName"]
        for page in iot.get_paginator("list_thing_groups").paginate(namePrefixFilter=group)
        for g in page.get("thingGroups", [])
    ]
    assert group in all_groups, f"{group} missing from ListThingGroups"

    # ListThings, read across every page, must surface the thing we created.
    listed = _eventually(
        lambda: [
            t["thingName"]
            for page in iot.get_paginator("list_things").paginate()
            for t in page.get("things", [])
        ],
        lambda ts: thing in ts,
        timeout_s=45,
        interval_s=2.0,
    )
    assert thing in listed, f"{thing} missing from ListThings: {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
