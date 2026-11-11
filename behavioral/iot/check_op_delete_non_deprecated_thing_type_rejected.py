"""op-delete-non-deprecated-thing-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-delete-non-deprecated-thing-type-rejected"
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
    """DeleteThingType must refuse a thing type that has not been deprecated first."""
    iot = ctx.client("iot")
    type_name = ctx.unique_name("sim2real-behav-thingtype-nodep-")
    iot.create_thing_type(thingTypeName=type_name)
    ctx.on_cleanup(lambda _n=type_name: _delete_thing_type(iot, _n))

    deprecated = iot.describe_thing_type(thingTypeName=type_name)["thingTypeMetadata"][
        "deprecated"
    ]
    assert deprecated is False, f"expected a freshly created thing type to be non-deprecated, got deprecated={deprecated!r}"

    code, message = _err(lambda: iot.delete_thing_type(thingTypeName=type_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = f"Cannot delete non deprecated thing type {type_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: still present, still not deprecated
    still_there = iot.describe_thing_type(thingTypeName=type_name)
    assert still_there["thingTypeName"] == type_name, (
        f"expected {type_name!r} to survive the rejected delete, describe returned {still_there.get('thingTypeName')!r}"
    )
    assert still_there["thingTypeMetadata"]["deprecated"] is False, (
        f"expected {type_name!r} to remain non-deprecated after the rejected delete, "
        f"got deprecated={still_there['thingTypeMetadata']['deprecated']!r}"
    )

    # a second immediate attempt is rejected the same way -- the rejection is a stable
    # state-machine property of "never deprecated", not a one-off fluke.
    code_again, message_again = _err(lambda: iot.delete_thing_type(thingTypeName=type_name))
    assert code_again == "InvalidRequestException", (
        f"expected the repeat delete to be rejected identically, got {code_again}"
    )
    assert message_again == expected, f"expected message {expected!r}, got {message_again!r}"
    still_there_again = iot.describe_thing_type(thingTypeName=type_name)
    assert still_there_again["thingTypeName"] == type_name, (
        f"expected {type_name!r} to still exist after the second rejected delete, "
        f"describe returned {still_there_again.get('thingTypeName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
