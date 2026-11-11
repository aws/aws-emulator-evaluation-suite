"""shadow-metadata-timestamp-per-leaf."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "shadow-metadata-timestamp-per-leaf"
GROUP = 'shadow'
SERVICES = ['iot']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


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
    """Shadow metadata mirrors the state's nesting with an integer epoch-seconds timestamp per leaf; an update
    advances only the written leaf's timestamp while untouched leaves keep their original one."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-meta-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps(
            {"state": {"desired": {"touched": 1, "untouched": 2, "cfg": {"deep": 3}}}}
        ),
    )
    ctx.on_cleanup(lambda _n=thing: iot_data.delete_thing_shadow(thingName=_n))

    first = _doc(iot_data.get_thing_shadow(thingName=thing))
    assert isinstance(first.get("timestamp"), int), (
        f"shadow document must carry an integer epoch-seconds timestamp: {first.get('timestamp')!r}"
    )
    meta = first["metadata"]["desired"]
    for leaf in ("touched", "untouched"):
        assert isinstance(meta[leaf].get("timestamp"), int), (
            f"metadata.desired.{leaf}.timestamp must be an integer, got {meta[leaf]!r}"
        )
    assert isinstance(meta["cfg"]["deep"].get("timestamp"), int), (
        f"metadata must mirror state's nesting down to every leaf, got {meta['cfg']!r}"
    )
    baseline_untouched = meta["untouched"]["timestamp"]

    def _rewrite_touched_leaf():
        """Rewrite only the 'touched' leaf, then re-read the merged document."""
        iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps({"state": {"desired": {"touched": 1}}}),
        )
        return _doc(iot_data.get_thing_shadow(thingName=thing))["metadata"]["desired"]

    # IoT stamps leaf timestamps at 1-second granularity, so poll (bounded) until the written
    # leaf's stamp is strictly newer than the baseline rather than sleeping and hoping.
    after = _poll(
        _rewrite_touched_leaf,
        lambda m: m["touched"]["timestamp"] > baseline_untouched,
        timeout_s=30,
        interval_s=1,
    )
    assert after["touched"]["timestamp"] > baseline_untouched, (
        "the written leaf's metadata timestamp must advance past the baseline; got "
        f"touched={after['touched']['timestamp']} baseline={baseline_untouched}"
    )
    assert after["untouched"]["timestamp"] == baseline_untouched, (
        "a leaf absent from the update must keep its ORIGINAL metadata timestamp; got "
        f"{after['untouched']['timestamp']} expected {baseline_untouched}"
    )
    assert after["cfg"]["deep"]["timestamp"] == meta["cfg"]["deep"]["timestamp"], (
        "an untouched NESTED leaf must keep its original metadata timestamp; got "
        f"{after['cfg']['deep']['timestamp']} expected {meta['cfg']['deep']['timestamp']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
