"""iot-shadow-update-with-a-stale-version-is-rejected-and-the-document-is-unchanged."""
from __future__ import annotations

import json
import socket
import time
from urllib.parse import urlsplit

from botocore.config import Config

from behavioral_harness import tags

CHECK = "iot-shadow-update-with-a-stale-version-is-rejected-and-the-document-is-unchanged"
GROUP = 'shadow-rejection'
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


def _error(fn):
    """The AWS (code, message) raised by ``fn``, or a loud sentinel if it wrongly SUCCEEDS.

    An unexpected success is the strongest signal available -- the target accepted input real
    AWS rejects -- so it must not come back as a falsy value that reads like a naming
    difference.
    """
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the code is the subject of the assertion
        resp = getattr(exc, "response", None) or {}
        error = resp.get("Error") or {}
        code = error.get("Code")
        return (code, error.get("Message")) if code else (f"NON-AWS-EXCEPTION:{type(exc).__name__}", None)
    return "UNEXPECTED-SUCCESS", None


def _shadow(iot_data, thing: str, name: str) -> dict:
    return json.loads(iot_data.get_thing_shadow(thingName=thing, shadowName=name)["payload"].read())


def _update(iot_data, thing: str, name: str, body: dict) -> dict:
    return json.loads(iot_data.update_thing_shadow(
        thingName=thing, shadowName=name, payload=json.dumps(body).encode(),
    )["payload"].read())


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A shadow update carrying a superseded version fails with ConflictException "Version
    conflict" and leaves the document and version unchanged, while the same body at the
    current version is accepted."""
    iot = ctx.client("iot")
    iot_data = _ats_data_client(ctx)
    thing = ctx.unique_name("sim2real-iot-thing-")
    shadow = "cfg"

    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": "shadow-conflict"}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))

    n = _update(iot_data, thing, shadow, {"state": {"reported": {"v": "first"}}})["version"]
    ctx.on_cleanup(lambda: iot_data.delete_thing_shadow(thingName=thing, shadowName=shadow))
    n_plus_1 = _update(iot_data, thing, shadow, {"state": {"reported": {"v": "second"}}})["version"]
    assert n_plus_1 == n + 1, f"the second update produced version {n_plus_1!r}, expected {n + 1!r}"

    # Break exactly one thing: the version the writer claims to be updating from.
    stale_body = {"version": n, "state": {"reported": {"v": "stale-writer"}}}
    code, message = _error(lambda: _update(iot_data, thing, shadow, stale_body))
    assert code == "ConflictException", (
        f"an update at superseded version {n!r} (current {n_plus_1!r}) raised {code!r}"
    )
    assert message == "Version conflict", message

    doc = _shadow(iot_data, thing, shadow)
    assert doc["state"]["reported"]["v"] == "second", (
        f"the refused write landed in the document anyway: {doc['state']!r}"
    )
    assert doc["version"] == n_plus_1, (
        f"the refused write moved the version to {doc['version']!r}, expected {n_plus_1!r}"
    )

    # POSITIVE CONTROL: the byte-identical state at the CURRENT version is accepted, so the
    # refusal above was about the version and nothing else.
    control_body = {"version": n_plus_1, "state": {"reported": {"v": "stale-writer"}}}
    control_version = _update(iot_data, thing, shadow, control_body)["version"]
    assert control_version == n_plus_1 + 1, (
        f"the control update returned version {control_version!r}, expected {n_plus_1 + 1!r}"
    )
    control_doc = _shadow(iot_data, thing, shadow)
    assert control_doc["state"]["reported"]["v"] == "stale-writer", (
        f"the accepted control write is not in the document: {control_doc['state']!r}"
    )
    assert control_doc["version"] == n_plus_1 + 1, (
        f"the accepted control write moved the version to {control_doc['version']!r}, "
        f"expected {n_plus_1 + 1!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
