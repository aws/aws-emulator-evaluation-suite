"""shadow-version-counter-survives-delete-and-recreate."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-version-counter-survives-delete-and-recreate"
GROUP = 'shadow-versioning'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message), or a sentinel pair if it
    unexpectedly SUCCEEDS.

    The sentinel is a non-code string on purpose: returning None/"" for "no error" would turn an
    emulator ACCEPTING input real AWS refuses — the strongest signal there is — into something
    that reads like a naming difference in the assert message.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>", None


def _doc(resp) -> dict:
    """Parse a shadow StreamingBody payload into a dict."""
    return json.loads(resp["payload"].read())


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """The shadow version counter is NOT reset by DeleteThingShadow, and the delete consumes one.

    After a shadow reaches version N, the delete reports N and the next create returns N + 2, so a
    device holding version N as its concurrency token cannot have a stale write accepted.
    """
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")
    thing = ctx.unique_name("sim2real-behav-iotdata-vercount-")

    # The registry thing is not required for a shadow (measured: UpdateThingShadow on an
    # unregistered name succeeds). It is created anyway so that a leaked shadow is VISIBLE:
    # a shadow's only handle is its thing name, no API lists shadows, and ListThings is the
    # only inventory a sweep can run.
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    first = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"n": 0}}})))
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))
    assert first["version"] == 1, (
        f"a shadow's first accepted update must be version 1, got {first['version']!r}"
    )

    second = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"n": 1}}})))
    assert second["version"] == 2, (
        f"version must advance by exactly 1 per accepted update, got {second['version']!r} after 1"
    )

    deleted = _doc(iot_data.delete_thing_shadow(thingName=thing))
    assert deleted["version"] == 2, (
        "DeleteThingShadow must report the version it deleted, expected 2, got "
        f"{deleted['version']!r}"
    )

    gone, gone_message = _error(lambda: iot_data.get_thing_shadow(thingName=thing))
    assert gone == "ResourceNotFoundException", (
        f"the shadow must be gone after DeleteThingShadow, got {gone!r}"
    )
    expected = f"No shadow exists with name: '{thing}'"
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    recreated = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"n": 9}}})))
    assert recreated["version"] == deleted["version"] + 2, (
        "the version counter must SURVIVE the delete and skip the number the delete consumed: "
        f"expected {deleted['version'] + 2} after deleting version {deleted['version']}, got "
        f"{recreated['version']!r}. A value of 1 means the counter was reset with the document, "
        f"which voids optimistic concurrency across a delete; a value of "
        f"{deleted['version'] + 1} means the delete did not consume a version."
    )

    # The re-created document is a fresh document, not a resurrection of the deleted one.
    assert recreated["state"]["reported"] == {"n": 9}, (
        "the re-created shadow must hold only the new state, not the deleted document's: "
        f"{recreated['state']['reported']!r}"
    )

    # And the surviving counter still gates a stale write against the PRE-DELETE version.
    stale, stale_message = _error(lambda: iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"version": deleted["version"], "state": {"reported": {"n": 99}}})))
    assert stale == "ConflictException", (
        "a write conditioned on the pre-delete version must still be refused after the "
        f"re-create, got {stale!r}"
    )
    assert stale_message == "Version conflict", stale_message
    survived = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert survived["state"]["reported"] == {"n": 9}, (
        f"the refused stale write must not have applied: {survived['state']['reported']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
