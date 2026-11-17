"""list-things-attribute-value-without-attribute-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-things-attribute-value-without-attribute-name-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]

_MARKER_ATTR = "sim2real-marker"
_MISSING_ATTRIBUTE_NAME = (
    "InvalidRequestException",
    "An attributeName is required to search for Things by attributeValue.",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _poll_until_seen(fn, wanted: str) -> None:
    """Retry ``fn()`` (a set of thing names) until it contains ``wanted`` or a deadline passes."""
    deadline = time.monotonic() + 60.0
    latest: set = set()
    while True:
        latest = fn()
        if wanted in latest:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"filtered listing never surfaced {wanted!r}; last saw {sorted(latest)!r}")
        time.sleep(2.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListThings with attributeValue but no attributeName is rejected, while the same filter
    with both parameters set still finds the thing it was searching for."""
    iot = ctx.client("iot")
    marker = ctx.unique_name("sim2real-behav-attrval-")
    name = ctx.unique_name("sim2real-behav-attrval-thing-")
    iot.create_thing(thingName=name, attributePayload={"attributes": {_MARKER_ATTR: marker}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=name))

    expect_error(lambda: iot.list_things(attributeValue=marker), *_MISSING_ATTRIBUTE_NAME)

    _poll_until_seen(
        lambda: {
            t["thingName"]
            for t in iot.list_things(attributeName=_MARKER_ATTR, attributeValue=marker).get("things", [])
        },
        name,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
