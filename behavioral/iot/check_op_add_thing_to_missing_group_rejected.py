"""op-add-thing-to-missing-group-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-add-thing-to-missing-group-rejected"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    success raises, so a target that accepts the call cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry writes asynchronously, so the first few
    reads after AddThingToThingGroup can still miss the membership.
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddThingToThingGroup must not lazily create a thing group that does not exist,
    and the rejection must be specific to the missing group -- not a stand-in for
    AddThingToThingGroup failing outright, which the positive control below rules out."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-nogrp-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    missing_group = ctx.unique_name("sim2real-behav-group-missing-")

    code, message = _err(
        lambda: iot.add_thing_to_thing_group(
            thingGroupName=missing_group, thingName=thing
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == (
        f"Cannot find requested thing group for accountId: {ctx.account} and thing group name: "
        f"{missing_group}"
    ), message

    describe_code, describe_message = _err(
        lambda: iot.describe_thing_group(thingGroupName=missing_group)
    )
    assert describe_code == "ResourceNotFoundException", describe_code
    assert describe_message == f"ThingGroup {ctx.account}:{missing_group} not found.", describe_message
    groups = iot.list_thing_groups_for_thing(thingName=thing).get("thingGroups", [])
    assert not any(g["groupName"] == missing_group for g in groups), groups

    # Positive control: the identical call against a real thing group succeeds, which is
    # what separates "rejects a group that does not exist" from "rejects every
    # AddThingToThingGroup call".
    real_group = ctx.unique_name("sim2real-behav-group-real-")
    iot.create_thing_group(thingGroupName=real_group)
    ctx.on_cleanup(lambda _n=real_group: iot.delete_thing_group(thingGroupName=_n))

    iot.add_thing_to_thing_group(thingGroupName=real_group, thingName=thing)
    groups_after = _eventually(
        lambda: iot.list_thing_groups_for_thing(thingName=thing).get("thingGroups", []),
        lambda gs: any(g["groupName"] == real_group for g in gs),
        timeout_s=90,
        interval_s=3,
    )
    assert any(g["groupName"] == real_group for g in groups_after), groups_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
