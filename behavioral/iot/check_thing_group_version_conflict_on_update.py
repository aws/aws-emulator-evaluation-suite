"""thing-group-version-conflict-on-update."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-group-version-conflict-on-update"
GROUP = 'thing-group'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _delete_thing_group(iot, name):
    """Best-effort teardown: delete a thing group."""
    iot.delete_thing_group(thingGroupName=name)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateThingGroup with a stale expectedVersion must fail with VersionConflictException,
    leave the group's properties and version untouched, and the correct version must still work."""
    iot = ctx.client("iot")
    group_name = ctx.unique_name("sim2real-behav-tg-ver-")
    iot.create_thing_group(thingGroupName=group_name)
    ctx.on_cleanup(lambda _n=group_name: _delete_thing_group(iot, _n))

    v0 = iot.describe_thing_group(thingGroupName=group_name)["version"]

    # Positive control: an update guarded by the current version succeeds.
    iot.update_thing_group(
        thingGroupName=group_name,
        thingGroupProperties={"thingGroupDescription": "v1"},
        expectedVersion=v0,
    )
    desc1 = iot.describe_thing_group(thingGroupName=group_name)
    v1 = desc1["version"]
    assert desc1["thingGroupProperties"]["thingGroupDescription"] == "v1", (
        f"positive control did not apply: {desc1['thingGroupProperties']}"
    )
    assert v1 == v0 + 1, f"expected version to advance by 1, got {v0} -> {v1}"

    # Break: reuse the now-stale expectedVersion (v0).
    code, message = _err(
        lambda: iot.update_thing_group(
            thingGroupName=group_name,
            thingGroupProperties={"thingGroupDescription": "won't apply"},
            expectedVersion=v0,
        )
    )
    assert code == "VersionConflictException", f"expected VersionConflictException, got {code}"
    assert message == f"The version for thing group {group_name} does not match the expected version.", message

    # Effect absent: an independent read shows neither the description nor the version moved.
    desc2 = iot.describe_thing_group(thingGroupName=group_name)
    assert desc2["thingGroupProperties"]["thingGroupDescription"] == "v1", (
        f"rejected update must not change state, got {desc2['thingGroupProperties']}"
    )
    assert desc2["version"] == v1, (
        f"rejected update must not advance version, got {v1} -> {desc2['version']}"
    )

    # Restore: the identical call now succeeds with the correct (current) version.
    iot.update_thing_group(
        thingGroupName=group_name,
        thingGroupProperties={"thingGroupDescription": "applied"},
        expectedVersion=v1,
    )
    desc3 = iot.describe_thing_group(thingGroupName=group_name)
    assert desc3["thingGroupProperties"]["thingGroupDescription"] == "applied", (
        f"expected 'applied' after correct-version update, got {desc3['thingGroupProperties']}"
    )
    assert desc3["version"] == v1 + 1, f"expected version to advance by 1, got {v1} -> {desc3['version']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
