"""shadow-without-registry-thing-and-named-shadow-listing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-without-registry-thing-and-named-shadow-listing"
GROUP = 'shadow-document'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message), or a sentinel pair if it
    unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>", None


def _delete_shadow(fn) -> None:
    """Teardown: the body deletes the named shadow itself, so ResourceNotFoundException is done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _doc(resp) -> dict:
    """Parse a shadow StreamingBody payload into a dict."""
    return json.loads(resp["payload"].read())


def _thing_registered(iot, thing: str) -> bool:
    """Whether a thing exists in the registry, paginating ListThings.

    The account may hold many things, so a single ListThings page proves nothing either way;
    the paginator is what bounds the answer.
    """
    for page in iot.get_paginator("list_things").paginate():
        if any(t["thingName"] == thing for t in page.get("things", [])):
            return True
    return False


def _named_shadows(iot_data, thing: str) -> list[str]:
    """Every named shadow on a thing, paginating ListNamedShadowsForThing."""
    names: list[str] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = iot_data.list_named_shadows_for_thing(thingName=thing, **kwargs)
        names.extend(page.get("results") or [])
        token = page.get("nextToken") or None
        if not token:
            return names


def _poll(fn, predicate, timeout_s: float = 30.0, interval_s: float = 1.0):
    """Poll fn() until predicate holds, tolerating transient exceptions; else AssertionError."""
    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A shadow needs NO registry thing, creates none, and the classic shadow is not a NAMED shadow.

    UpdateThingShadow on an unregistered name succeeds without adding it to ListThings, and
    ListNamedShadowsForThing lists only the named shadow, never the classic one.
    """
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")
    # Deliberately NOT created in the registry. A shadow on an unregistered thing has no List*
    # handle, so the cleanup below is the only thing that removes it.
    thing = ctx.unique_name("sim2real-behav-iotdata-noreg-")
    named = "sim2real-behav-cfg"

    assert not _thing_registered(iot, thing), (
        f"setup: {thing!r} must not exist in the registry before the test"
    )
    absent, absent_message = _error(lambda: iot_data.get_thing_shadow(thingName=thing))
    assert absent == "ResourceNotFoundException", (
        f"setup: {thing!r} must start with no shadow, got {absent!r}"
    )
    expected = f"No shadow exists with name: '{thing}'"
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    created = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"unregistered": True}}})))
    ctx.on_cleanup(lambda _n=thing: _delete_shadow(lambda: iot_data.delete_thing_shadow(thingName=_n)))
    assert created["version"] == 1, (
        "a shadow on an UNREGISTERED thing must be created at version 1 — an emulator that "
        f"enforces a registry foreign key refuses this call outright; got {created['version']!r}"
    )
    assert created["state"]["reported"] == {"unregistered": True}, (
        f"the shadow must persist its state, got {created['state']!r}"
    )

    # And the write did not conjure a registry entry.
    assert not _thing_registered(iot, thing), (
        f"the data plane must not create a registry thing for {thing!r} — auto-registration makes "
        f"ListThings stop being an inventory of what the customer created"
    )
    round_trip = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert round_trip["state"]["reported"] == {"unregistered": True}, (
        f"the shadow must be readable back without a registry thing, got {round_trip['state']!r}"
    )

    # The classic shadow exists, and it is NOT a named shadow.
    assert _named_shadows(iot_data, thing) == [], (
        "a thing whose only shadow is the classic one must list NO named shadows; got "
        f"{_named_shadows(iot_data, thing)!r} — the classic shadow leaking into `results` (often "
        f"as an empty-string name) is the shape of this bug"
    )

    named_doc = _doc(iot_data.update_thing_shadow(
        thingName=thing, shadowName=named,
        payload=json.dumps({"state": {"reported": {"scope": "named"}}})))
    ctx.on_cleanup(
        lambda _n=thing, _s=named: _delete_shadow(
            lambda: iot_data.delete_thing_shadow(thingName=_n, shadowName=_s)))
    assert named_doc["version"] == 1, (
        "the named shadow is an INDEPENDENT document and must start its own version at 1, got "
        f"{named_doc['version']!r}"
    )

    results = _poll(lambda: _named_shadows(iot_data, thing), lambda names: named in names)
    assert results == [named], (
        f"ListNamedShadowsForThing must return exactly the one named shadow, got {results!r}"
    )

    # Deleting the named shadow empties the listing and leaves the classic document alone.
    iot_data.delete_thing_shadow(thingName=thing, shadowName=named)
    emptied = _poll(lambda: _named_shadows(iot_data, thing), lambda names: named not in names)
    assert emptied == [], f"the listing must be empty again after the delete, got {emptied!r}"
    classic = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert classic["state"]["reported"] == {"unregistered": True}, (
        f"deleting the named shadow must not disturb the classic document, got {classic['state']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
