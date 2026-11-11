"""shadow-oversize-document-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "shadow-oversize-document-rejected"
GROUP = 'shadow'
SERVICES = ['iot']

# AWS IoT Device Shadow service limit: a shadow document is capped at 8 KB. 64 KB is well
# clear of the boundary so the check does not depend on the exact byte accounting.
_OVERSIZE_BYTES = 64 * 1024


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


def _doc(resp) -> dict:
    """Parse a shadow StreamingBody payload into a dict."""
    return json.loads(resp["payload"].read())


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateThingShadow refuses a document over the 8 KB limit with RequestEntityTooLargeException and AWS's
    exact message, the shadow's state and version 1 stay unchanged, and an in-limit update then gives version 2."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-size-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    baseline = _doc(
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps({"state": {"desired": {"small": "x" * 1024}}}),
        )
    )
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))
    assert baseline["version"] == 1, f"setup: expected version 1, got {baseline['version']}"

    oversize = json.dumps({"state": {"desired": {"blob": "y" * _OVERSIZE_BYTES}}})
    assert len(oversize) > 8 * 1024, f"test payload must exceed the 8 KB limit, got {len(oversize)}"
    code, code_message = _error(lambda: iot_data.update_thing_shadow(thingName=thing, payload=oversize))
    assert code == "RequestEntityTooLargeException", (
        f"expected RequestEntityTooLargeException for a {len(oversize)}-byte shadow document, got {code}"
    )
    # AWS sizes the compact desired-section object, not the whole request payload.
    assert code_message == "Json document too large.  Size is " + str(len(json.dumps({"blob": "y" * _OVERSIZE_BYTES}, separators=(",", ":")))) + ", max allowed: 8192", (
        f"expected the exact {code} message, got {code_message!r}"
    )

    # Effect absent: neither the state nor the version moved.
    unchanged = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert unchanged["version"] == 1, (
        f"a refused update must not advance the shadow version, got {unchanged['version']}"
    )
    assert "blob" not in unchanged["state"]["desired"], (
        f"the refused document must not be partially applied: {sorted(unchanged['state']['desired'])}"
    )
    assert unchanged["state"]["desired"]["small"] == "x" * 1024, (
        "the pre-existing state must be intact after the refusal"
    )

    # Control: the shadow is still writable with an in-limit document. The terminal assertion
    # is an independent read (get_thing_shadow), not the update call's own echoed response.
    iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"desired": {"ok": True}}})
    )
    restored = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert restored["version"] == 2, (
        f"an in-limit update after the refusal must be accepted as version 2, got {restored['version']}"
    )
    assert restored["state"]["desired"]["ok"] is True, (
        f"the in-limit update must be visible on an independent read: {restored['state']['desired']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
