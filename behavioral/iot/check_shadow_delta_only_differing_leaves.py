"""shadow-delta-only-differing-leaves."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "shadow-delta-only-differing-leaves"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A shadow's delta holds only the leaves where desired differs from reported, at two nesting levels: an
    equal leaf is absent and its differing sibling carries the desired value; delta disappears once they agree."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-delta-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps(
            {
                "state": {
                    "desired": {"agree": "same", "differ": "wanted", "cfg": {"p": 1, "q": 2}},
                    "reported": {"agree": "same", "differ": "actual", "cfg": {"p": 1, "q": 9}},
                }
            }
        ),
    )
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))

    state = _doc(iot_data.get_thing_shadow(thingName=thing))["state"]
    delta = state.get("delta")
    assert delta is not None, f"delta must be present when desired and reported differ: {state}"

    assert "agree" not in delta, (
        f"a leaf whose reported value already equals desired must NOT appear in delta: {delta}"
    )
    assert delta.get("differ") == "wanted", (
        f"delta must carry the DESIRED value for a differing leaf, got {delta.get('differ')!r}"
    )
    assert "cfg" in delta, f"a nested subtree with a differing leaf must appear in delta: {delta}"
    assert "p" not in delta["cfg"], (
        f"nested leaf 'p' agrees, so it must NOT appear in delta.cfg: {delta['cfg']}"
    )
    assert delta["cfg"].get("q") == 2, (
        f"delta.cfg must carry the desired value for the differing nested leaf: {delta['cfg']}"
    )
    assert delta != state["desired"], (
        "delta must be COMPUTED, not a copy of the desired document; an emulator that echoes "
        f"desired as delta is wrong: delta={delta} desired={state['desired']}"
    )

    # Reporting the remaining difference must retract delta entirely — it is derived, not stored.
    iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"reported": {"differ": "wanted", "cfg": {"q": 2}}}}),
    )
    settled = _doc(iot_data.get_thing_shadow(thingName=thing))["state"]
    assert "delta" not in settled, (
        f"delta must disappear once reported matches desired everywhere: {settled}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
