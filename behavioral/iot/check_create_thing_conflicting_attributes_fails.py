"""create-thing-conflicting-attributes-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-thing-conflicting-attributes-fails"
GROUP = 'thing-lifecycle'
SERVICES = ['iot']

def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateThing with the same name but different attributes must fail (not silently overwrite),
    and the conflict is specifically about the pre-existing name: once it is gone, the identical
    call succeeds."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-thing-conflict-")
    iot.create_thing(thingName=name, attributePayload={"attributes": {"model": "x1"}})
    ctx.on_cleanup(lambda _n=name: iot.delete_thing(thingName=_n))

    conflicting_create = lambda: iot.create_thing(
        thingName=name, attributePayload={"attributes": {"model": "different"}}
    )
    err = _error(conflicting_create)
    assert err == ("ResourceAlreadyExistsException", f"Thing {name} already exists in account with different attributes"), err

    desc = iot.describe_thing(thingName=name)
    assert desc["attributes"] == {"model": "x1"}, (
        f"attributes must remain unchanged from the original create, got {desc['attributes']}"
    )

    # restore: remove the conflicting thing, then the identical call must succeed
    iot.delete_thing(thingName=name)

    not_found = _error(lambda: iot.describe_thing(thingName=name))
    assert not_found == ("ResourceNotFoundException", f"Thing {ctx.account}:{name} not found."), not_found

    mutate_dead = _error(
        lambda: iot.update_thing(thingName=name, attributePayload={"attributes": {"model": "y"}})
    )
    assert mutate_dead == ("ResourceNotFoundException", f"Thing {name} not found."), mutate_dead

    conflicting_create()
    desc_after_restore = iot.describe_thing(thingName=name)
    assert desc_after_restore["attributes"] == {"model": "different"}, (
        f"identical call must now succeed once the name is free, got {desc_after_restore['attributes']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
