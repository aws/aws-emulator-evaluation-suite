"""create-describe-delete-thing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-describe-delete-thing"
GROUP = 'thing-lifecycle'
SERVICES = ['iot']

def _error(fn):
    """The AWS (code, HTTP status, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response["Error"].get("Message"),
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_not_found(err, what: str) -> None:
    """Grade a not-found on code, HTTP status and a non-empty message, never wording."""
    code, status, message = err
    assert code == "ResourceNotFoundException", f"{what}: expected ResourceNotFoundException, got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected HTTP 4xx, got {status!r}"
    assert message, f"{what}: expected a non-empty not-found message"


def _delete_if_present(iot, name: str) -> None:
    """Teardown: delete the thing, tolerating one the body already deleted."""
    try:
        iot.delete_thing(thingName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _things_with_attribute(iot, name: str) -> list[str]:
    """Every thing carrying this check's own sim2real-check attribute, fully paginated."""
    out: list[str] = []
    for page in iot.get_paginator("list_things").paginate(attributeName="sim2real-check", attributeValue=name):
        out += [t["thingName"] for t in page.get("things", [])]
    return out


def _await_listing(iot, name: str, expected: list[str], timeout_s: float = 120.0) -> None:
    """Poll the attribute-filtered listing, an eventually consistent index, until it equals ``expected``."""
    deadline = time.monotonic() + timeout_s
    while True:
        listed = _things_with_attribute(iot, name)
        if listed == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"list_things filtered to this check's attribute: expected {expected!r} within {timeout_s:.0f}s, got {listed!r}"
            )
        time.sleep(5.0)

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Thing state machine: create -> describe and the attribute-filtered listing reflect it -> delete
    -> describe 404, unlisted, update refused."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-thing-")
    iot.create_thing(thingName=name, attributePayload={"attributes": {"sim2real-check": name}})
    ctx.on_cleanup(lambda _n=name: _delete_if_present(iot, _n))

    desc = iot.describe_thing(thingName=name)
    assert desc["thingName"] == name, f"expected thingName {name!r}, got {desc.get('thingName')!r}"
    assert desc["version"] == 1, f"expected version 1, got {desc.get('version')!r}"

    _await_listing(iot, name, [name])

    iot.delete_thing(thingName=name)

    # Beat 1: the read by id is a ResourceNotFoundException/404.
    _assert_not_found(_error(lambda: iot.describe_thing(thingName=name)), "DescribeThing")
    # Beat 2: the attribute-filtered listing no longer holds it.
    _await_listing(iot, name, [])
    # Beat 3: a mutation on the dead name is refused with not-found.
    _assert_not_found(
        _error(lambda: iot.update_thing(thingName=name, attributePayload={"attributes": {"x": "y"}})),
        "UpdateThing",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
