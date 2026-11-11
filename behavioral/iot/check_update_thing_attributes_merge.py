"""update-thing-attributes-merge."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-thing-attributes-merge"
GROUP = 'thing-lifecycle'
SERVICES = ['iot']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateThing replaces the attribute map by default; merge=True unions it instead."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-thing-merge-")
    iot.create_thing(
        thingName=name, attributePayload={"attributes": {"a": "1", "b": "2"}}
    )
    ctx.on_cleanup(lambda _n=name: iot.delete_thing(thingName=_n))
    initial_version = iot.describe_thing(thingName=name)["version"]
    assert initial_version == 1, initial_version

    # merge=True: existing untouched keys survive, listed keys are overwritten/added
    iot.update_thing(
        thingName=name,
        attributePayload={"attributes": {"b": "updated", "c": "3"}, "merge": True},
    )
    desc = iot.describe_thing(thingName=name)
    assert desc["attributes"] == {"a": "1", "b": "updated", "c": "3"}, desc["attributes"]
    assert desc["version"] == 2, desc["version"]

    # default (merge omitted / False): the attribute map is REPLACED wholesale
    iot.update_thing(thingName=name, attributePayload={"attributes": {"d": "4"}})
    desc2 = iot.describe_thing(thingName=name)
    assert desc2["attributes"] == {"d": "4"}, desc2["attributes"]
    assert desc2["version"] == 3, desc2["version"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
