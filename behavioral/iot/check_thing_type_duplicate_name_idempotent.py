"""thing-type-duplicate-name-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-type-duplicate-name-idempotent"
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

def _delete_thing_type(iot, type_name):
    """Best-effort teardown: real AWS requires deprecate (+ a wait) before delete; emulators
    may allow an immediate delete."""
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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateThingType is idempotent for an identical re-create (same ARN returned),
    but re-creating the same name with DIFFERENT properties must be rejected."""
    iot = ctx.client("iot")
    type_name = ctx.unique_name("sim2real-behav-thingtype-dup-")
    check_tags = [{"Key": "sim2real", "Value": CHECK}]
    r1 = iot.create_thing_type(thingTypeName=type_name, tags=check_tags)
    ctx.on_cleanup(lambda _n=type_name: _delete_thing_type(iot, _n))

    # Identical re-create (same tags too -- real AWS counts a tags mismatch as a
    # property mismatch) is idempotent on real AWS -- it does NOT raise.
    r2 = iot.create_thing_type(thingTypeName=type_name, tags=check_tags)
    assert r1["thingTypeArn"] == r2["thingTypeArn"], (
        f"identical re-create must be idempotent: {r1['thingTypeArn']} vs {r2['thingTypeArn']}"
    )

    # Conflicting properties for an existing name must be rejected. Tags stay
    # identical so only thingTypeProperties differs from r1/r2.
    code, message = _err(
        lambda: iot.create_thing_type(
            thingTypeName=type_name,
            thingTypeProperties={"thingTypeDescription": "conflicting-description"},
            tags=check_tags,
        )
    )
    assert code == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException for conflicting properties, got {code}"
    )
    assert message == f"Thing Type {type_name} already exists in current account with different properties", message

    # Terminal read, independent of the rejected call: the conflicting create must
    # have had zero effect on the stored type -- description stays whatever it was
    # before the rejected attempt (unset by this check's own create).
    desc = iot.describe_thing_type(thingTypeName=type_name)
    stored_description = desc.get("thingTypeProperties", {}).get("thingTypeDescription")
    assert stored_description is None, (
        f"rejected conflicting create must not have applied its properties: "
        f"describe_thing_type shows thingTypeDescription={stored_description!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
