"""shadow-update-get-delta-and-delete-lifecycle."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError, HTTPClientError
from botocore.exceptions import ConnectionError as BotoConnectionError

from behavioral_harness import tags

CHECK = "shadow-update-get-delta-and-delete-lifecycle"
GROUP = 'shadow'
SERVICES = ['iot']


#: Codes a target answers when no data plane serves the operation at the discovered endpoint.
_ABSENT_CODES = ("UnknownOperationException", "NotImplemented", "NotImplementedException", "InvalidAction")


def _reach_data_plane(fn, what: str):
    """Make the first data-plane call; an unreachable or absent data plane raises the sentinel."""
    try:
        return fn()
    except (BotoConnectionError, HTTPClientError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: {what}: nothing answered at the iot:Data-ATS endpoint ({exc!r})"
        ) from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in _ABSENT_CODES:
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: {what}: the iot:Data-ATS endpoint does not serve the operation ({code})"
            ) from exc
        raise

def _error(fn) -> tuple[str, int, str]:
    """Call fn(); return its botocore error (code, HTTP status, message). An unexpected SUCCESS
    raises rather than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _assert_not_found(fn, what: str, expected_message: str) -> None:
    """Grade the not-found fn() raises on code, HTTP status and the exact message."""
    code, status, message = _error(fn)
    assert code == "ResourceNotFoundException", f"{what}: expected ResourceNotFoundException, got {code!r}"
    assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
    assert message == expected_message, f"{what}: expected the message {expected_message!r}, got {message!r}"


def _named_shadows(iot_data, thing: str) -> list[str]:
    """Every named shadow of ``thing``, following nextToken. A thing with no shadow left may
    answer ResourceNotFoundException instead of an empty page; both mean nothing is listed."""
    out: list[str] = []
    kwargs = {"thingName": thing}
    while True:
        try:
            page = iot_data.list_named_shadows_for_thing(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or out:
                raise
            return out
        out += page.get("results", [])
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _delete_thing_if_present(iot, thing: str) -> None:
    """Teardown: delete the thing, tolerating one the body already deleted."""
    try:
        iot.delete_thing(thingName=thing)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_shadow_if_present(iot_data, thing: str, shadow: str) -> None:
    """Teardown: delete the named shadow, tolerating one already gone with its thing."""
    try:
        iot_data.delete_thing_shadow(thingName=thing, shadowName=shadow)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _iot_data(ctx):
    """iot-data must hit the account-specific ATS data-plane endpoint the target publishes —
    the control-plane host answers shadow/retained-message ops with UnknownOperationException.
    Discover it via DescribeEndpoint(iot:Data-ATS) and reach it through ctx.endpoint_url."""
    ep = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(ep))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Named-shadow lifecycle: update creates v1 -> delta reflects desired/reported diff -> listed ->
    delete -> get 404, unlisted, a second delete 404 -> the thing is deleted and reads 404."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-")
    shadow = ctx.unique_name("s")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: _delete_thing_if_present(iot, _n))

    payload = json.dumps({"state": {"desired": {"color": "red", "on": True}}})
    r1 = _reach_data_plane(
        lambda: iot_data.update_thing_shadow(thingName=thing, shadowName=shadow, payload=payload),
        "UpdateThingShadow",
    )
    ctx.on_cleanup(lambda: _delete_shadow_if_present(iot_data, thing, shadow))
    doc1 = json.loads(r1["payload"].read())
    assert doc1["version"] == 1, f"expected version 1 on shadow creation, got {doc1.get('version')}"
    assert doc1["state"]["desired"] == {"color": "red", "on": True}, (
        f"expected desired echo {{'color': 'red', 'on': True}}, got {doc1['state'].get('desired')}"
    )

    got = iot_data.get_thing_shadow(thingName=thing, shadowName=shadow)
    got_doc = json.loads(got["payload"].read())
    assert got_doc["state"]["delta"] == {"color": "red", "on": True}, (
        f"expected delta {{'color': 'red', 'on': True}} with no reported state yet, "
        f"got {got_doc['state'].get('delta')}"
    )

    r2 = iot_data.update_thing_shadow(
        thingName=thing,
        shadowName=shadow,
        payload=json.dumps({"state": {"reported": {"color": "red", "on": True}}}),
    )
    doc2 = json.loads(r2["payload"].read())
    assert doc2["version"] == 2, f"expected version 2 after second update, got {doc2.get('version')}"

    got2 = iot_data.get_thing_shadow(thingName=thing, shadowName=shadow)
    got2_doc = json.loads(got2["payload"].read())
    assert "delta" not in got2_doc["state"], f"expected no delta once reported matches desired, got {got2_doc['state']!r}"

    listed = _named_shadows(iot_data, thing)
    assert shadow in listed, f"ListNamedShadowsForThing does not hold the shadow: {listed!r}"

    iot_data.delete_thing_shadow(thingName=thing, shadowName=shadow)
    # Beat 1: the read by name is a 404 naming the shadow.
    _assert_not_found(
        lambda: iot_data.get_thing_shadow(thingName=thing, shadowName=shadow), "GetThingShadow",
        f"No shadow exists with name: '{shadow}'",
    )
    # Beat 2: the thing's named-shadow listing no longer holds it.
    after = _named_shadows(iot_data, thing)
    assert shadow not in after, f"ListNamedShadowsForThing still holds the deleted shadow: {after!r}"
    # Beat 3: an update would recreate the shadow, so the mutation on the dead shadow is a second delete.
    _assert_not_found(
        lambda: iot_data.delete_thing_shadow(thingName=thing, shadowName=shadow), "a second DeleteThingShadow",
        f"No shadow exists with name: '{shadow}'",
    )

    iot.delete_thing(thingName=thing)
    _assert_not_found(
        lambda: iot.describe_thing(thingName=thing), "DescribeThing after DeleteThing",
        f"Thing {ctx.account}:{thing} not found.",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
