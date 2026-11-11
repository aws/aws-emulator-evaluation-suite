"""iot-named-shadow-delta-and-version-monotonicity-across-updates."""
from __future__ import annotations

import json
import socket
import time
from urllib.parse import urlsplit

from botocore.config import Config

from behavioral_harness import tags

CHECK = "iot-named-shadow-delta-and-version-monotonicity-across-updates"
GROUP = 'shadow-data-plane'
SERVICES = ['iot']


def _ats_data_client(ctx):
    """An ``iot-data`` client bound to the account's own iot:Data-ATS host.

    The control-plane host answers shadow ops with UnknownOperationException, so the endpoint is
    discovered. An account's first DescribeEndpoint creates the hostname, whose DNS record can be
    missing for tens of seconds and then resolve intermittently, so this waits for the record and
    widens botocore's retries for EndpointConnectionError.
    """
    host = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    url = ctx.endpoint_url(host)
    dialled = urlsplit(url).hostname
    deadline = time.time() + 180
    last = None
    while time.time() < deadline:
        try:
            socket.getaddrinfo(dialled, 443)
            return ctx.client(
                "iot-data",
                endpoint_url=url,
                config=Config(retries={"max_attempts": 10, "mode": "standard"}),
            )
        except OSError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(f"the ATS endpoint {dialled!r} never resolved in DNS: {last!r}")


def _shadow(iot_data, thing: str, name: str) -> dict:
    return json.loads(iot_data.get_thing_shadow(thingName=thing, shadowName=name)["payload"].read())


def _update(iot_data, thing: str, name: str, body: dict) -> dict:
    return json.loads(iot_data.update_thing_shadow(
        thingName=thing, shadowName=name, payload=json.dumps(body).encode(),
    )["payload"].read())


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A named shadow derives state.delta from desired versus reported, drops it once
    reported matches, advances one version per update, stamps leaf timestamps, and is listed
    for the thing."""
    iot = ctx.client("iot")
    iot_data = _ats_data_client(ctx)
    thing = ctx.unique_name("sim2real-iot-thing-")
    shadow = "cfg"

    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": "shadow-delta"}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))

    desired = {"a": 1, "b": "x"}
    accepted = _update(iot_data, thing, shadow, {"state": {"desired": desired}})
    ctx.on_cleanup(lambda: iot_data.delete_thing_shadow(thingName=thing, shadowName=shadow))
    assert accepted["version"] == 1, f"a brand-new shadow started at version {accepted['version']!r}"

    first = _shadow(iot_data, thing, shadow)
    assert first["state"]["delta"] == desired, (
        f"a desired-only shadow reported delta {first['state'].get('delta')!r}, expected {desired!r}"
    )
    assert "reported" not in first["state"], (
        f"the service invented a reported section: {first['state']!r}"
    )

    _update(iot_data, thing, shadow, {"state": {"reported": desired}})
    second = _shadow(iot_data, thing, shadow)
    assert second["version"] == first["version"] + 1, (
        f"the version went {first['version']!r} -> {second['version']!r}, expected exactly +1"
    )
    assert "delta" not in second["state"], (
        f"the delta survived a matching reported update: {second['state']!r}"
    )
    assert second["state"]["reported"] == desired, f"{second['state']!r}"
    assert second["state"]["desired"] == desired, (
        f"the reported update clobbered desired: {second['state']!r}"
    )
    assert isinstance(second["metadata"]["reported"]["a"]["timestamp"], int), (
        f"no per-leaf metadata timestamp on reported.a: {second['metadata']!r}"
    )
    assert (second["metadata"]["reported"]["a"]["timestamp"]
            >= second["metadata"]["desired"]["a"]["timestamp"]), (
        f"reported.a is stamped older than desired.a it answered: {second['metadata']!r}"
    )

    # A third update touching ONE leaf must re-open the delta for that leaf only.
    _update(iot_data, thing, shadow, {"state": {"desired": {"b": "y"}}})
    third = _shadow(iot_data, thing, shadow)
    assert third["version"] == second["version"] + 1, (
        f"the version went {second['version']!r} -> {third['version']!r}, expected exactly +1"
    )
    assert third["state"]["delta"] == {"b": "y"}, (
        f"a one-leaf desired change produced delta {third['state'].get('delta')!r}, expected "
        f"{{'b': 'y'}} -- the unchanged leaf 'a' must not appear"
    )

    named = iot_data.list_named_shadows_for_thing(thingName=thing)
    assert shadow in named["results"], f"ListNamedShadowsForThing returned {named['results']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
