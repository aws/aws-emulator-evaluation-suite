"""shadow-unknown-state-node-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-unknown-state-node-rejected"
GROUP = 'shadow-document'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _error_code(fn):
    """Call fn(); return the botocore Error.Code, or a sentinel if it unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>"


def _error_message(fn):
    """Call fn(); return the botocore Error.Message, or a sentinel if it SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>"


def _doc(resp) -> dict:
    """Parse a shadow StreamingBody payload into a dict."""
    return json.loads(resp["payload"].read())


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """``state`` is a CLOSED vocabulary: a section other than desired/reported is refused whole.

    It is InvalidRequestException "State contains an invalid node: 'bogus'", and the state, version
    and metadata stay unchanged with the shadow still writable, since ``delta`` derives from them.
    """
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")
    thing = ctx.unique_name("sim2real-behav-iotdata-statenode-")

    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    baseline = _doc(iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"reported": {"keep": "original"},
                                      "desired": {"keep": "original"}}})))
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))
    assert baseline["version"] == 1, f"setup: expected version 1, got {baseline['version']!r}"

    bad = json.dumps({"state": {"bogus": {"x": 1}}})
    code = _error_code(lambda: iot_data.update_thing_shadow(thingName=thing, payload=bad))
    assert code == "InvalidRequestException", (
        f"an undefined `state` section must be refused with InvalidRequestException, got {code!r}"
    )
    message = _error_message(lambda: iot_data.update_thing_shadow(thingName=thing, payload=bad))
    assert message == "State contains an invalid node: 'bogus'", (
        "the refusal must NAME the offending node — an emulator answering a generic message "
        f"leaves the caller unable to fix the document; got {message!r}"
    )

    # Effect absent: nothing about the stored document moved.
    unchanged = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert unchanged["version"] == 1, (
        f"a refused update must not advance the version, got {unchanged['version']!r}"
    )
    assert set(unchanged["state"]) == {"reported", "desired"}, (
        "the refused section must not appear in the stored document, whose sections are "
        f"{sorted(unchanged['state'])}"
    )
    assert unchanged["state"]["reported"] == {"keep": "original"}, (
        f"the pre-existing reported state must be intact, got {unchanged['state']['reported']!r}"
    )
    assert set(unchanged["metadata"]) == {"reported", "desired"}, (
        f"metadata must mirror only the real sections, got {sorted(unchanged['metadata'])}"
    )

    # Control, in the same file: a legal section on the same shadow is still accepted.
    after = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"keep": "updated"}}})))
    assert after["version"] == 2, (
        f"a legal update after the refusal must be accepted as version 2, got {after['version']!r}"
    )

    # Terminal read independent of the mutating call: the control update really stuck.
    confirmed = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert confirmed["version"] == 2, (
        f"an independent read after the control update must also see version 2, got "
        f"{confirmed['version']!r}"
    )
    assert confirmed["state"]["reported"] == {"keep": "updated"}, (
        "an independent read after the control update must see the new reported state, got "
        f"{confirmed['state']['reported']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
