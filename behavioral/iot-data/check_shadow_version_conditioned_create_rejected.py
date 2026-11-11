"""shadow-version-conditioned-create-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-version-conditioned-create-rejected"
GROUP = 'shadow-versioning'
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


def _doc(resp) -> dict:
    """Parse a shadow StreamingBody payload into a dict."""
    return json.loads(resp["payload"].read())


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A version-conditioned UpdateThingShadow against a shadow that does not exist is a CONFLICT.

    ConflictException / HTTP 409 "Version conflict" leaves no document behind, and a create on
    ``version: 0`` then lands at version 1, so the refusal consumed nothing.
    """
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")
    thing = ctx.unique_name("sim2real-behav-iotdata-vercreate-")

    # Registered so a leaked shadow is visible in ListThings — a shadow itself is unlistable.
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    # Registered BEFORE the create it undoes, because the create under test is one AWS might
    # wrongly accept: if it does, the shadow exists and the assertion two lines down aborts.
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))

    no_shadow = f"No shadow exists with name: '{thing}'"
    absent, absent_message = _error(lambda: iot_data.get_thing_shadow(thingName=thing))
    assert absent == "ResourceNotFoundException", (
        f"setup: this thing must start with no shadow, got {absent!r}"
    )
    assert absent_message == no_shadow, f"expected message {no_shadow!r}, got {absent_message!r}"

    code, message = _error(lambda: iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"version": 1, "state": {"reported": {"conditioned": True}}})))
    assert code == "ConflictException", (
        "a version-conditioned update against a nonexistent shadow must be refused with "
        f"ConflictException, got {code!r}"
    )
    assert message == "Version conflict", message

    # Effect absent: the refusal created nothing.
    still_absent, still_absent_message = _error(lambda: iot_data.get_thing_shadow(thingName=thing))
    assert still_absent == "ResourceNotFoundException", (
        "a refused version-conditioned create must not leave a shadow behind, got "
        f"{still_absent!r}"
    )
    assert still_absent_message == no_shadow, (
        f"expected message {no_shadow!r}, got {still_absent_message!r}"
    )

    # Positive control, at the exact boundary the refusal above claims to police: `version: 0`
    # against an absent shadow is the one conditioned value real AWS accepts as a create, so this
    # catches a target that rejects every explicit `version` on a create, not only one that
    # upserts unconditionally. Same operation as the refused call two lines up; only the version
    # number differs.
    control_resp = iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"version": 0, "state": {"reported": {"conditioned": True}}}))
    control_doc = _doc(control_resp)
    assert control_doc["version"] == 1, (
        "a version:0 conditioned create against an absent shadow must be ACCEPTED and start at "
        f"version 1 — a higher number means the refused call above still consumed a version, got "
        f"{control_doc['version']!r}"
    )

    # Terminal read: independent of the create that just ran, at the destination — not the
    # mutating call's own response.
    persisted = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert persisted["version"] == 1, (
        f"the version:0 control create must persist at version 1, got {persisted['version']!r}"
    )
    assert persisted["state"]["reported"] == {"conditioned": True}, (
        f"the control create must persist its state, got {persisted['state']['reported']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
