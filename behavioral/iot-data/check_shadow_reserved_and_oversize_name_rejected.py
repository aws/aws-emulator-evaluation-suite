"""shadow-reserved-and-oversize-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-reserved-and-oversize-name-rejected"
GROUP = 'shadow-naming'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
_MAX_SHADOW_NAME = 64


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """shadowName has two limits the SMITHY MODEL DOES NOT DESCRIBE, and the 64-char edge is legal.

    64 characters is accepted and listed; 65 is "Bad Request" and a reserved ``$aws`` name "Invalid
    shadow name" (InvalidRequestException), and neither refused name leaves a shadow behind.
    """
    iot = ctx.client("iot")
    iot_data = ctx.client("iot-data")
    thing = ctx.unique_name("sim2real-behav-iotdata-shname-")

    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    # Control FIRST and exactly AT the declared maximum: 64 characters is legal.
    legal = ("sim2real-behav-" + "n" * _MAX_SHADOW_NAME)[:_MAX_SHADOW_NAME]
    assert len(legal) == _MAX_SHADOW_NAME, f"test bug: {len(legal)}"
    ctx.on_cleanup(
        lambda _n=thing, _s=legal: iot_data.delete_thing_shadow(thingName=_n, shadowName=_s))
    accepted = _doc(iot_data.update_thing_shadow(
        thingName=thing, shadowName=legal,
        payload=json.dumps({"state": {"reported": {"edge": "ok"}}})))
    assert accepted["version"] == 1, (
        f"a {_MAX_SHADOW_NAME}-character shadow name is legal and its shadow must be created at "
        f"version 1, got {accepted['version']!r}"
    )
    listed = _poll(lambda: _named_shadows(iot_data, thing), lambda names: legal in names)
    assert listed == [legal], (
        f"only the one legal named shadow may exist, ListNamedShadowsForThing returned {listed!r}"
    )

    # Rule 1: one character over the declared maximum.
    too_long = legal + "z"
    ctx.on_cleanup(
        lambda _n=thing, _s=too_long: iot_data.delete_thing_shadow(thingName=_n, shadowName=_s))
    long_code = _error_code(lambda: iot_data.update_thing_shadow(
        thingName=thing, shadowName=too_long,
        payload=json.dumps({"state": {"reported": {"edge": "too-long"}}})))
    assert long_code == "InvalidRequestException", (
        f"a {len(too_long)}-character shadow name must be refused with InvalidRequestException, "
        f"got {long_code!r}"
    )
    long_message = _error_message(lambda: iot_data.update_thing_shadow(
        thingName=thing, shadowName=too_long,
        payload=json.dumps({"state": {"reported": {"edge": "too-long"}}})))
    assert long_message == "Bad Request", (
        f"expected the (deliberately terse) message 'Bad Request', got {long_message!r}"
    )

    # Rule 2: the reserved $-prefixed namespace, which the model's own pattern permits.
    reserved = "$aws-sim2real-behav"
    ctx.on_cleanup(
        lambda _n=thing, _s=reserved: iot_data.delete_thing_shadow(thingName=_n, shadowName=_s))
    reserved_code = _error_code(lambda: iot_data.update_thing_shadow(
        thingName=thing, shadowName=reserved,
        payload=json.dumps({"state": {"reported": {"edge": "reserved"}}})))
    assert reserved_code == "InvalidRequestException", (
        f"the reserved shadow name {reserved!r} must be refused with InvalidRequestException, got "
        f"{reserved_code!r} — the Smithy pattern ^[$a-zA-Z0-9:_-]+$ allows '$', so an emulator "
        f"validating from the model alone accepts it"
    )
    reserved_message = _error_message(lambda: iot_data.update_thing_shadow(
        thingName=thing, shadowName=reserved,
        payload=json.dumps({"state": {"reported": {"edge": "reserved"}}})))
    assert reserved_message == f"Invalid shadow name : {reserved}", (
        f"the reserved-name refusal must echo the offending name, got {reserved_message!r}"
    )

    # Effect absent: neither refused name created a shadow, and the legal one is untouched.
    final = _named_shadows(iot_data, thing)
    assert final == [legal], (
        "the two refused names must not have created shadows; ListNamedShadowsForThing returned "
        f"{final!r}, expected only {legal!r}"
    )
    survivor = _doc(iot_data.get_thing_shadow(thingName=thing, shadowName=legal))
    assert survivor["version"] == 1, (
        f"the legal named shadow must be untouched by the refusals, got version "
        f"{survivor['version']!r}"
    )
    assert survivor["state"]["reported"] == {"edge": "ok"}, (
        f"the legal named shadow's state must be intact, got {survivor['state']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
