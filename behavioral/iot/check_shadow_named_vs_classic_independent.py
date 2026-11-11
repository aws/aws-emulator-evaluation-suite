"""shadow-named-vs-classic-independent."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-named-vs-classic-independent"
GROUP = 'shadow'
SERVICES = ['iot']

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _iot_data(ctx):
    """iot-data must hit the account-specific ATS data-plane endpoint on real AWS — the
    control-plane host answers shadow/retained-message ops with UnknownOperationException.
    Discover it via DescribeEndpoint(iot:Data-ATS) and route it through ctx.endpoint_url. (Transient connect blips are absorbed by the client's
    standard-retry mode.)"""
    ep = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(ep))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A named shadow is a document independent from the classic (unnamed) shadow on the same thing."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-named-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"scope": "classic"}}})
    )
    iot_data.update_thing_shadow(
        thingName=thing,
        shadowName="config",
        payload=json.dumps({"state": {"reported": {"scope": "named"}}}),
    )

    classic = json.loads(iot_data.get_thing_shadow(thingName=thing)["payload"].read())
    named = json.loads(
        iot_data.get_thing_shadow(thingName=thing, shadowName="config")["payload"].read()
    )
    assert classic["state"]["reported"] == {"scope": "classic"}, (
        f"expected classic shadow reported state {{'scope': 'classic'}}, "
        f"got {classic['state']['reported']!r}"
    )
    assert named["state"]["reported"] == {"scope": "named"}, (
        f"expected named shadow 'config' reported state {{'scope': 'named'}}, "
        f"got {named['state']['reported']!r}"
    )

    # deleting the named shadow must not remove the classic shadow
    iot_data.delete_thing_shadow(thingName=thing, shadowName="config")
    still_classic = json.loads(iot_data.get_thing_shadow(thingName=thing)["payload"].read())
    assert still_classic["state"]["reported"] == {"scope": "classic"}, (
        f"deleting the named shadow 'config' must not affect the classic shadow; "
        f"expected {{'scope': 'classic'}}, got {still_classic['state']['reported']!r}"
    )
    named_gone, named_gone_message = _error(
        lambda: iot_data.get_thing_shadow(thingName=thing, shadowName="config")
    )
    assert named_gone == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted named shadow 'config', "
        f"got {named_gone!r}"
    )
    assert named_gone_message == "No shadow exists with name: 'config'", (
        f"expected the exact {named_gone} message, got {named_gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
