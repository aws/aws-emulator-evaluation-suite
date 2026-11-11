"""create-thing-idempotent-same-attributes."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-thing-idempotent-same-attributes"
GROUP = 'thing-lifecycle'
SERVICES = ['iot']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateThing is idempotent when called again with identical attributes."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-thing-idem-")
    attrs = {"attributes": {"model": "x1"}}
    r1 = iot.create_thing(thingName=name, attributePayload=attrs)
    ctx.on_cleanup(lambda _n=name: iot.delete_thing(thingName=_n))

    r2 = iot.create_thing(thingName=name, attributePayload=attrs)
    assert r1["thingId"] == r2["thingId"], "idempotent CreateThing must return same thingId"

    desc = iot.describe_thing(thingName=name)
    assert desc["attributes"] == {"model": "x1"}, f"expected attributes to survive the idempotent create, got {desc['attributes']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
