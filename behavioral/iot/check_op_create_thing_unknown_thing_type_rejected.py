"""op-create-thing-unknown-thing-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-create-thing-unknown-thing-type-rejected"
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

def _delete_thing_type(iot, type_name):
    """Best-effort teardown: real AWS requires deprecate (+ a wait) before delete."""
    try:
        iot.deprecate_thing_type(thingTypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_thing_type(thingTypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateThing referencing a thing type that does not exist must not auto-create it."""
    iot = ctx.client("iot")

    # Positive control: CreateThing with a thing type that DOES exist succeeds, so the
    # rejection below is shown to be specific to the missing reference -- not a symptom
    # of every CreateThing call carrying a thingTypeName failing.
    known_type = ctx.unique_name("sim2real-behav-thingtype-known-")
    iot.create_thing_type(thingTypeName=known_type, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda _n=known_type: _delete_thing_type(iot, _n))
    control_thing = ctx.unique_name("sim2real-behav-thing-control-")
    iot.create_thing(thingName=control_thing, thingTypeName=known_type)
    ctx.on_cleanup(lambda _n=control_thing: iot.delete_thing(thingName=_n))
    control_described = iot.describe_thing(thingName=control_thing)
    assert control_described.get("thingTypeName") == known_type, (
        f"positive control: expected thingTypeName={known_type!r}, got {control_described!r}"
    )

    thing = ctx.unique_name("sim2real-behav-thing-badtype-")
    missing_type = ctx.unique_name("sim2real-behav-thingtype-missing-")

    code, message = _err(
        lambda: iot.create_thing(thingName=thing, thingTypeName=missing_type)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Thing Type {ctx.account}:{missing_type} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # neither the thing nor the referenced type may have been created
    code, message = _err(lambda: iot.describe_thing(thingName=thing))
    assert code == "ResourceNotFoundException", (
        f"thing must not exist after a create rejected for an unknown thing type, got {code}"
    )
    expected = f"Thing {ctx.account}:{thing} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code, message = _err(lambda: iot.describe_thing_type(thingTypeName=missing_type))
    assert code == "ResourceNotFoundException", (
        f"a referenced-but-missing thing type must not be auto-created, got {code}"
    )
    expected = f"Thing Type {ctx.account}:{missing_type} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Restore: once the referenced type actually exists, the identical CreateThing call succeeds.
    iot.create_thing_type(thingTypeName=missing_type, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda _n=missing_type: _delete_thing_type(iot, _n))
    iot.create_thing(thingName=thing, thingTypeName=missing_type)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    restored = iot.describe_thing(thingName=thing)
    assert restored.get("thingTypeName") == missing_type, (
        f"restore: expected thingTypeName={missing_type!r}, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
