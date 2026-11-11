"""op-delete-thing-stale-expected-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-delete-thing-stale-expected-version-rejected"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteThing with a stale expectedVersion must fail optimistic locking, not delete;
    the identical call with the correct expectedVersion must then succeed and actually delete."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-optlock-")
    iot.create_thing(thingName=thing, attributePayload={"attributes": {"a": "1"}})
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    # bump version to 2 so expectedVersion=1 is stale
    iot.update_thing(thingName=thing, attributePayload={"attributes": {"a": "2"}})
    current_version = iot.describe_thing(thingName=thing)["version"]
    assert current_version == 2, f"expected version 2 after update, got {current_version}"

    code, message = _err(lambda: iot.delete_thing(thingName=thing, expectedVersion=1))
    assert code == "VersionConflictException", f"expected VersionConflictException, got {code}"
    expected = f"The version for thing {thing} does not match the expected version."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the thing must still exist and be untouched
    desc = iot.describe_thing(thingName=thing)
    assert desc["version"] == 2, f"expected version to remain 2, got {desc['version']}"
    assert desc["attributes"] == {"a": "2"}, desc["attributes"]

    # the identical call with the correct (current) expectedVersion must succeed
    iot.delete_thing(thingName=thing, expectedVersion=current_version)
    code, message = _err(lambda: iot.describe_thing(thingName=thing))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Thing {ctx.account}:{thing} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
