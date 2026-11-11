"""iot-concurrent-shadow-updates-converge-to-one-final-version."""
from __future__ import annotations

import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from botocore.config import Config

from behavioral_harness import tags

CHECK = "iot-concurrent-shadow-updates-converge-to-one-final-version"
GROUP = 'concurrency'
SERVICES = ['iot']

_WRITERS = 8


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


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Eight simultaneous unversioned shadow updates are each accepted with distinct consecutive
    versions or refused with ConflictException "Version conflict", and the final document holds
    every accepted writer's key."""
    iot = ctx.client("iot")
    iot_data = _ats_data_client(ctx)
    thing = ctx.unique_name("sim2real-iot-thing-")
    shadow = "cfg"

    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": "shadow-concurrent"}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))

    seeded = json.loads(iot_data.update_thing_shadow(
        thingName=thing, shadowName=shadow,
        payload=json.dumps({"state": {"reported": {"seed": True}}}).encode(),
    )["payload"].read())
    ctx.on_cleanup(lambda: iot_data.delete_thing_shadow(thingName=thing, shadowName=shadow))
    start_version = seeded["version"]

    def _writer(i: int):
        try:
            body = json.loads(iot_data.update_thing_shadow(
                thingName=thing, shadowName=shadow,
                payload=json.dumps({"state": {"reported": {f"k{i}": i}}}).encode(),
            )["payload"].read())
            return (i, "accepted", body["version"])
        except Exception as exc:  # noqa: BLE001 - a refusal is data, not a verdict
            resp = getattr(exc, "response", None) or {}
            err = resp.get("Error") or {}
            return (i, "refused", err.get("Code") or type(exc).__name__, err.get("Message"))

    with ThreadPoolExecutor(max_workers=_WRITERS) as pool:
        outcomes = list(pool.map(_writer, range(_WRITERS)))

    accepted = [o for o in outcomes if o[1] == "accepted"]
    refused = [o[:3] for o in outcomes if o[1] == "refused"]
    refusal_messages = [o[3] for o in outcomes if o[1] == "refused"]
    returned_versions = sorted(o[2] for o in accepted)

    assert len(accepted) >= 1, f"every concurrent writer was refused: {outcomes!r}"
    # Usually all eight unversioned writers are accepted,
    # but a loser is sometimes refused ConflictException even though it sent NO version -- the
    # optimistic-concurrency check is applied against the internal counter either way. So the
    # count of accepted writers is not an AWS guarantee and is not asserted; the guarantee is
    # that every refusal is that one code and that the accepted writers got a clean run of
    # versions.
    refusal_codes = [o[2] for o in refused]
    assert all(code == "ConflictException" for code in refusal_codes), (
        f"a concurrent unversioned writer was refused with something other than a version "
        f"conflict: {refused!r}"
    )
    assert all(message == "Version conflict" for message in refusal_messages), refusal_messages
    expected_run = list(range(start_version + 1, start_version + len(accepted) + 1))
    assert returned_versions == expected_run, (
        f"the {len(accepted)!r} accepted writers were handed versions {returned_versions!r}, "
        f"expected the consecutive run {expected_run!r} -- a repeat or a gap means the version "
        f"counter is not the serialisation point"
    )

    final = _shadow(iot_data, thing, shadow)
    assert final["version"] == start_version + len(accepted), (
        f"the final version is {final['version']!r}, expected {start_version!r} + "
        f"{len(accepted)!r} accepted updates"
    )
    reported = final["state"]["reported"]
    missing = [f"k{i}" for i, _, _ in accepted if f"k{i}" not in reported]
    assert not missing, (
        f"the merge dropped accepted writers {missing!r}; the document holds {sorted(reported)!r}"
    )
    assert reported["seed"] is True, (
        f"the concurrent merge clobbered the pre-existing seed key: {reported!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
