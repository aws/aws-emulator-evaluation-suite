"""create-thing-conflicting-type-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-thing-conflicting-type-fails"
GROUP = 'thing-lifecycle'
SERVICES = ['iot']

def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _delete_thing_type(iot, type_name):
    """Teardown: AWS deletes a thing type only 5 minutes after it is deprecated, so retry the
    delete on that refusal for a bounded window; emulators may allow an immediate delete."""
    iot.deprecate_thing_type(thingTypeName=type_name)
    deadline = time.monotonic() + 420
    while True:
        try:
            iot.delete_thing_type(thingTypeName=type_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() > deadline:
                raise
        time.sleep(20)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an existing thing with a different thingTypeName must fail."""
    iot = ctx.client("iot")
    type_name = ctx.unique_name("sim2real-behav-thingtype-")
    iot.create_thing_type(thingTypeName=type_name)
    ctx.on_cleanup(lambda _n=type_name: _delete_thing_type(iot, _n))

    name = ctx.unique_name("sim2real-behav-thing-conflict-")
    iot.create_thing(thingName=name)
    ctx.on_cleanup(lambda _n=name: iot.delete_thing(thingName=_n))

    err = _error(lambda: iot.create_thing(thingName=name, thingTypeName=type_name))
    assert err == ("ResourceAlreadyExistsException", f"Thing {name} already exists in account with different attributes"), err

    # the rejected call must not have attached the conflicting type — independent read
    desc = iot.describe_thing(thingName=name)
    assert desc.get("thingTypeName") is None, (
        f"expected no thingTypeName after rejected conflicting CreateThing, got {desc.get('thingTypeName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
