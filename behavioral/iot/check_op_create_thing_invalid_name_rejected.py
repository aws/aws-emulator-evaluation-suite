"""op-create-thing-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-create-thing-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _rejects(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Thing names must match [a-zA-Z0-9:_-]+; a name with a space must be rejected."""
    iot = ctx.client("iot")

    # positive control: prove this account/target can create a thing at all, so the
    # rejection below cannot be mistaken for "every CreateThing fails here"
    good_name = ctx.unique_name("sim2real-behav-thing-good-")
    iot.create_thing(thingName=good_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=good_name))
    desc = iot.describe_thing(thingName=good_name)
    assert desc["thingName"] == good_name, f"expected {good_name}, got {desc.get('thingName')}"

    bad_name = ctx.unique_name("sim2real-behav-thing-bad ") + " name"
    code, message = _rejects(lambda: iot.create_thing(thingName=bad_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = (
        f"1 validation error detected: Value '{bad_name}' at 'thingName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9:_-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # and nothing may have been persisted under that name
    not_found, message = _rejects(lambda: iot.describe_thing(thingName=bad_name))
    assert not_found == "InvalidRequestException", not_found
    expected = (
        f"1 validation error detected: Value '{bad_name}' at 'thingName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9:_-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
