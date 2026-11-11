"""thing-type-lifecycle-deprecate-undeprecate."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "thing-type-lifecycle-deprecate-undeprecate"
GROUP = 'thing-type'
SERVICES = ['iot']

def _delete_thing_type(iot, name):
    """Best-effort teardown: deprecate then delete a thing type."""
    try:
        iot.deprecate_thing_type(thingTypeName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_thing_type(thingTypeName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Thing type: create -> associate with a thing (immutable once set) -> deprecate -> undeprecate."""
    iot = ctx.client("iot")
    type_name = ctx.unique_name("sim2real-behav-thingtype-")
    iot.create_thing_type(
        thingTypeName=type_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda _n=type_name: _delete_thing_type(iot, _n))

    thing_name = ctx.unique_name("sim2real-behav-thing-typed-")
    iot.create_thing(thingName=thing_name, thingTypeName=type_name)
    ctx.on_cleanup(lambda _n=thing_name: iot.delete_thing(thingName=_n))

    desc = iot.describe_thing(thingName=thing_name)
    assert desc["thingTypeName"] == type_name, (
        f"expected thingTypeName {type_name!r}, got {desc.get('thingTypeName')!r}"
    )
    fresh_meta = iot.describe_thing_type(thingTypeName=type_name)["thingTypeMetadata"]
    assert fresh_meta["deprecated"] is False, (
        f"expected deprecated=False on a freshly created thing type, got {fresh_meta['deprecated']!r}"
    )

    # The thing-type association is removable, and removal is reflected in describe.
    iot.update_thing(thingName=thing_name, removeThingType=True)
    desc_after = iot.describe_thing(thingName=thing_name)
    assert "thingTypeName" not in desc_after or not desc_after.get("thingTypeName"), (
        f"expected no thingTypeName after removeThingType, got {desc_after.get('thingTypeName')!r}"
    )

    iot.deprecate_thing_type(thingTypeName=type_name)
    deprecated_meta = iot.describe_thing_type(thingTypeName=type_name)["thingTypeMetadata"]
    assert deprecated_meta["deprecated"] is True, (
        f"expected deprecated=True after DeprecateThingType, got {deprecated_meta['deprecated']!r}"
    )

    iot.deprecate_thing_type(thingTypeName=type_name, undoDeprecate=True)
    undeprecated_meta = iot.describe_thing_type(thingTypeName=type_name)["thingTypeMetadata"]
    assert undeprecated_meta["deprecated"] is False, (
        f"expected deprecated=False after undoDeprecate, got {undeprecated_meta['deprecated']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
