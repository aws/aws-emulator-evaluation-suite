"""shadow-client-token-echoed-not-persisted."""
from __future__ import annotations

import json
import re
import socket
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "shadow-client-token-echoed-not-persisted"
GROUP = 'shadow'
SERVICES = ['iot']

# Top-level keys the persisted shadow document is allowed to have. Request-only control keys
# (clientToken, version) must never appear here.
_ALLOWED_DOC_KEYS = {"state", "metadata", "version", "timestamp"}


def _iot_data(ctx):
    """iot-data must hit an ATS data-plane host — the control-plane host answers shadow and
    retained-message ops with UnknownOperationException. Prefer the account-specific endpoint
    from DescribeEndpoint(iot:Data-ATS) on every target, dialled through ctx.endpoint_url.

    The DNS guard is load-bearing, not defensive dressing:
    DescribeEndpoint(iot:Data-ATS) returns a well-formed account host
    (<prefix>-ats.iot.<region>.amazonaws.com) that does NOT resolve from every network — the
    resolver answers NXDOMAIN, so botocore fails with EndpointConnectionError before it can
    sign anything, and the whole check dies on an infrastructure detail that has nothing to do
    with the behavior under test. The SDK's own regional default for this service,
    data-ats.iot.<region>.amazonaws.com, resolves and serves the SAME account, because the
    account is selected by the SigV4 credentials and not by the hostname. So: use the account host when it resolves, fall back to the regional
    default when it does not, and never silently fall back to the control-plane host."""
    ep = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", ep) and "-ats.iot." in ep, (
        f"DescribeEndpoint(iot:Data-ATS) must return an ATS data-plane host, got {ep!r}"
    )
    url = ctx.endpoint_url(ep)
    try:
        socket.getaddrinfo(urlsplit(url).hostname, 443)
    except socket.gaierror:
        return ctx.client("iot-data")
    return ctx.client("iot-data", endpoint_url=url)


def _doc(resp) -> dict:
    """Parse a shadow StreamingBody payload into a dict."""
    return json.loads(resp["payload"].read())


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """``clientToken`` and ``version`` are request-only control keys: echoed, never persisted into state.

    A shadow stored by merging the request body would leak both keys into the document every device
    reads back as if they were settings.
    """
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-token-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    token = "sim2real-behav-tok-1"
    accepted = _doc(
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps({"clientToken": token, "state": {"desired": {"a": 1}}}),
        )
    )
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))
    # The UpdateThingShadow REST reply is exactly
    # {"state","metadata","version","timestamp","clientToken"} — it echoes clientToken and does NOT
    # contain a computed delta. Both halves are pinned, because the reply and the stored document
    # differ in BOTH directions (see the delta assertion below) and an emulator that returns the
    # stored document as the reply, or stores the reply, gets one of them wrong.
    assert accepted.get("clientToken") == token, (
        f"UpdateThingShadow must echo the request clientToken, got {accepted.get('clientToken')!r}"
    )
    assert set(accepted) == {"state", "metadata", "version", "timestamp", "clientToken"}, (
        f"unexpected UpdateThingShadow reply keys: {sorted(accepted)}"
    )
    assert "delta" not in accepted["state"], (
        f"the update REPLY carries no computed delta, only what was written: {sorted(accepted['state'])}"
    )
    assert accepted["version"] == 1, f"first accepted update must be version 1, got {accepted['version']}"

    stored = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert "clientToken" not in stored, (
        f"clientToken is a request-only control key and must not be persisted: {sorted(stored)}"
    )
    # The mirror image of the reply: the STORED document has no clientToken but does carry the
    # server-computed delta (desired with no matching reported), so the two documents are not
    # interchangeable in either direction.
    assert stored["state"].get("delta") == {"a": 1}, (
        f"the stored document must carry the computed delta for a desired-only shadow, got "
        f"{stored['state'].get('delta')!r}"
    )
    assert set(stored) <= _ALLOWED_DOC_KEYS, (
        f"persisted shadow document has unexpected top-level keys: {sorted(set(stored) - _ALLOWED_DOC_KEYS)}"
    )
    assert stored["state"]["desired"] == {"a": 1}, (
        f"only the state subtree may be persisted, got {stored['state']['desired']}"
    )

    # A version-conditioned update must not leak the precondition into state either.
    conditioned = _doc(
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps(
                {"clientToken": "sim2real-behav-tok-2", "version": 1, "state": {"desired": {"b": 2}}}
            ),
        )
    )
    assert conditioned["version"] == 2, (
        f"a correctly-conditioned update must advance to version 2, got {conditioned['version']}"
    )
    final = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert final["state"]["desired"] == {"a": 1, "b": 2}, (
        f"state must hold exactly the merged settings, got {final['state']['desired']}"
    )
    assert set(final) <= _ALLOWED_DOC_KEYS, (
        f"persisted document leaked request control keys: {sorted(set(final) - _ALLOWED_DOC_KEYS)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
