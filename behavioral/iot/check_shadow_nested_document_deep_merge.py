"""shadow-nested-document-deep-merge."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "shadow-nested-document-deep-merge"
GROUP = 'shadow'
SERVICES = ['iot']


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateThingShadow merges nested objects leaf by leaf, so sibling leaves and subtrees survive a partial
    update, and the shadow version advances by exactly 1 per accepted update."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-merge-deep-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    r1 = _doc(
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps(
                {
                    "state": {
                        "desired": {
                            "cfg": {"a": 1, "b": 2, "nested": {"x": 10, "y": 20}},
                            "top": "keep",
                        }
                    }
                }
            ),
        )
    )
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))
    assert r1["version"] == 1, f"first accepted shadow update must be version 1, got {r1['version']}"

    # Touch exactly ONE leaf two levels down. Everything else must survive.
    r2 = _doc(
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps({"state": {"desired": {"cfg": {"nested": {"x": 99}}}}}),
        )
    )
    assert r2["version"] == 2, f"version must advance by exactly 1, got {r2['version']} after v1"

    merged = _doc(iot_data.get_thing_shadow(thingName=thing))["state"]["desired"]
    assert merged["cfg"]["nested"] == {"x": 99, "y": 20}, (
        f"depth-3 sibling leaf 'y' must survive a merge that only set 'x': {merged['cfg']['nested']}"
    )
    assert merged["cfg"]["a"] == 1 and merged["cfg"]["b"] == 2, (
        f"depth-2 siblings 'a'/'b' must survive: {merged['cfg']}"
    )
    assert merged["top"] == "keep", f"depth-1 sibling 'top' must survive: {merged}"

    # A brand-new nested branch is ADDED, not substituted for the existing one.
    r3 = _doc(
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps({"state": {"desired": {"other": {"z": 5}}}}),
        )
    )
    assert r3["version"] == 3, f"version must advance by exactly 1, got {r3['version']} after v2"

    final = _doc(iot_data.get_thing_shadow(thingName=thing))["state"]["desired"]
    assert final["other"] == {"z": 5}, f"new nested branch missing: {final}"
    assert final["cfg"]["nested"] == {"x": 99, "y": 20}, (
        f"adding a new branch must not disturb the existing one: {final['cfg']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
