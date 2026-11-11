"""shadow-malformed-json-payload-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-malformed-json-payload-rejected"
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """UpdateThingShadow's body is a JSON document, and the three ways it can fail to be one.

    Non-JSON and empty bodies are "Payload contains invalid json", a state-less document "Missing
    required node: state" (both HTTP 400), and the existing shadow is left undisturbed.
    """
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")
    thing = ctx.unique_name("sim2real-behav-iotdata-badjson-")

    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    baseline = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"keep": "original"}}})))
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))
    assert baseline["version"] == 1, f"setup: expected version 1, got {baseline['version']!r}"

    # Every one of these is InvalidRequestException; the MESSAGE is what separates a parse
    # failure from a schema failure, so each is asserted exactly.
    cases = [
        (b"sim2real-behav-not-json-at-all", "Payload contains invalid json", "unparseable bytes"),
        (b"", "Payload contains invalid json", "an empty body"),
        (b"[1, 2, 3]", "Missing required node: state", "JSON that is not an object"),
        (json.dumps({"desired": {"x": 1}}).encode(), "Missing required node: state",
         "an object with no `state` node"),
    ]
    for payload, want_message, label in cases:
        code = _error_code(
            lambda _p=payload: iot_data.update_thing_shadow(thingName=thing, payload=_p))
        assert code == "InvalidRequestException", (
            f"{label} must be refused with InvalidRequestException, got {code!r}"
        )
        message = _error_message(
            lambda _p=payload: iot_data.update_thing_shadow(thingName=thing, payload=_p))
        assert message == want_message, (
            f"{label} must be refused with {want_message!r}, got {message!r} — a single generic "
            f"message for both the parse and the schema failure is not the same contract"
        )

    # Effect absent: none of the four refusals touched the stored document or the counter.
    unchanged = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert unchanged["version"] == 1, (
        f"{len(cases)} refused updates must leave the version at 1, got {unchanged['version']!r}"
    )
    assert unchanged["state"] == {"reported": {"keep": "original"}}, (
        f"the stored document must be byte-for-byte the baseline, got {unchanged['state']!r}"
    )

    # Control, in the same file: a well-formed document on the same shadow is still accepted.
    after = _doc(iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"keep": "updated"}}})))
    assert after["version"] == 2, (
        "a well-formed update after the refusals must be accepted as version 2, got "
        f"{after['version']!r}"
    )

    # Terminal read is independent of the mutating call: a target that echoes an unpersisted
    # version in the update response, but never actually stores it, must not pass here.
    final = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert final["version"] == 2, (
        f"an independent read after the accepted update must show version 2, got {final['version']!r}"
    )
    assert final["state"]["reported"] == {"keep": "updated"}, (
        "an independent read after the accepted update must show the new document, got "
        f"{final['state']['reported']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
