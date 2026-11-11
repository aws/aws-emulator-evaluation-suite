"""thing-type-premature-deletion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-type-premature-deletion-rejected"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteThingType right after DeprecateThingType fails InvalidRequestException with AWS's exact
    wait-5-minutes message, twice, and the thing type survives and stays deprecated."""
    iot = ctx.client("iot")

    thing_type_name = ctx.unique_name("sim2real-iot-tt-")
    iot.create_thing_type(
        thingTypeName=thing_type_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _try_delete(iot, thing_type_name))
    iot.deprecate_thing_type(thingTypeName=thing_type_name, undoDeprecate=False)

    code, message = _error_code(lambda: iot.delete_thing_type(thingTypeName=thing_type_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"Cannot delete thing type : {thing_type_name}. Please wait for 5 minutes after deprecation and then retry", message

    # Effect absent: the thing type must still exist, still deprecated.
    still_there = iot.describe_thing_type(thingTypeName=thing_type_name)
    assert still_there["thingTypeName"] == thing_type_name, still_there
    assert still_there["thingTypeMetadata"]["deprecated"] is True, still_there["thingTypeMetadata"]

    # A second immediate attempt is rejected the same way -- the rejection is a stable
    # state-machine property of the deprecation window, not a one-off fluke.
    code_again, message_again = _error_code(lambda: iot.delete_thing_type(thingTypeName=thing_type_name))
    assert code_again == "InvalidRequestException", f"expected InvalidRequestException, got {code_again}"
    assert message_again == f"Cannot delete thing type : {thing_type_name}. Please wait for 5 minutes after deprecation and then retry", message_again
    still_there_again = iot.describe_thing_type(thingTypeName=thing_type_name)
    assert still_there_again["thingTypeMetadata"]["deprecated"] is True, still_there_again["thingTypeMetadata"]


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _try_delete(iot, thing_type_name: str) -> bool:
    try:
        iot.delete_thing_type(thingTypeName=thing_type_name)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return False


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
