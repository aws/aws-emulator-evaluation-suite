"""thing-type-deprecated-blocks-new-thing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-type-deprecated-blocks-new-thing"
GROUP = 'thing-type'
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A deprecated thing type cannot be associated with a newly created thing; un-deprecating
    restores the identical call to success."""
    iot = ctx.client("iot")
    type_name = ctx.unique_name("sim2real-behav-thingtype-dep-")
    iot.create_thing_type(thingTypeName=type_name)
    ctx.on_cleanup(lambda _n=type_name: _delete_thing_type(iot, _n))

    # Positive control: the type works before it is deprecated, so a later rejection is
    # attributable to the deprecation and not to every create_thing call with a thingTypeName.
    control_name = ctx.unique_name("sim2real-behav-thing-control-")
    iot.create_thing(thingName=control_name, thingTypeName=type_name)
    ctx.on_cleanup(lambda _n=control_name: iot.delete_thing(thingName=_n))
    control_desc = iot.describe_thing(thingName=control_name)
    assert control_desc["thingTypeName"] == type_name, (
        f"expected control thing to carry {type_name!r}, got {control_desc.get('thingTypeName')!r}"
    )

    iot.deprecate_thing_type(thingTypeName=type_name)

    thing_name = ctx.unique_name("sim2real-behav-thing-blocked-")
    code, message = _err(
        lambda: iot.create_thing(thingName=thing_name, thingTypeName=type_name)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"Can not create new thing with depreated thing type:{type_name}", message

    # confirm it never got created
    not_found_code, not_found_message = _err(lambda: iot.describe_thing(thingName=thing_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code}"
    )
    assert not_found_message == f"Thing {ctx.account}:{thing_name} not found.", not_found_message

    # Restore: undo the deprecation and demand the identical call now succeeds.
    iot.deprecate_thing_type(thingTypeName=type_name, undoDeprecate=True)
    ctx.on_cleanup(lambda _n=thing_name: iot.delete_thing(thingName=_n))
    iot.create_thing(thingName=thing_name, thingTypeName=type_name)
    restored_desc = iot.describe_thing(thingName=thing_name)
    assert restored_desc["thingTypeName"] == type_name, (
        f"expected restored thing to carry {type_name!r}, got {restored_desc.get('thingTypeName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
