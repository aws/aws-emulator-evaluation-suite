"""concurrent-shadow-version-conditioned-updates."""
from __future__ import annotations

import concurrent.futures
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-shadow-version-conditioned-updates"
GROUP = 'concurrency'
SERVICES = ['iot']

def _iot_data(ctx):
    """iot-data must hit the account-specific ATS data-plane endpoint on real AWS — the
    control-plane host answers shadow/retained-message ops with UnknownOperationException.
    Discover it via DescribeEndpoint(iot:Data-ATS) and route it through ctx.endpoint_url. (Transient connect blips are absorbed by the client's
    standard-retry mode.)"""
    ep = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(ep))


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """N racers CAS-updating a shadow off the same base version: exactly one wins, rest get Conflict."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-race-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    base = iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"counter": 0}}})
    )
    base_version = json.loads(base["payload"].read())["version"]

    n = 6

    def racer(i: int):
        return iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps(
                {"state": {"reported": {"counter": i}}, "version": base_version}
            ),
        )

    # Fire N conditioned updates at once; capture each outcome (result OR the
    # raised exception) so we can assert on the distribution rather than losing
    # all-but-one to the first raise.
    fns = [lambda i=i: racer(i) for i in range(n)]
    results: list = [None] * n
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        futs = {ex.submit(fn): idx for idx, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(futs):
            idx = futs[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for distribution assertions
                results[idx] = exc

    n_success = sum(1 for r in results if not isinstance(r, BaseException))
    codes = [
        r.response.get("Error", {}).get("Code")
        for r in results
        if isinstance(r, ClientError)
    ]

    assert n_success == 1, f"expected exactly 1 winner, got {n_success}"
    assert len(codes) == n - 1, codes
    assert all(c == "ConflictException" for c in codes), codes
    messages = [
        r.response.get("Error", {}).get("Message")
        for r in results
        if isinstance(r, ClientError)
    ]
    assert all(message == "Version conflict" for message in messages), messages

    final = json.loads(iot_data.get_thing_shadow(thingName=thing)["payload"].read())
    assert final["version"] == base_version + 1, final["version"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
