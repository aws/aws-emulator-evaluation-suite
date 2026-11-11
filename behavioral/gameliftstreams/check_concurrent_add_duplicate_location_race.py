"""concurrent-add-duplicate-location-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-add-duplicate-location-race"
GROUP = "concurrency"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AddStreamGroupLocations calls adding the same location leave exactly one LocationState for
    it; at least one call succeeds and any loser fails with ValidationException.
    """
    gl = ctx.client("gameliftstreams")
    primary = ctx.region
    secondary = next(loc for loc in ("us-east-1", "us-west-2", "eu-west-1") if loc != primary)

    try:
        sg = gl.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": primary, "MaximumCapacity": 2}],
            Tags={"sim2real-env": "test"},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no Gen4n GPU quota in this Region ({e}); GameLift Streams GPU "
                "quotas default to 0 and must be explicitly requested"
            )
        raise
    sg_arn = sg["Arn"]
    ctx.on_cleanup(lambda: gl.delete_stream_group(Identifier=sg_arn))
    _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn),
        lambda r: r["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=900.0,
        interval_s=15.0,
    )

    def racer():
        return _error_code(
            lambda: gl.add_stream_group_locations(
                Identifier=sg_arn,
                LocationConfigurations=[{"LocationName": secondary, "MaximumCapacity": 2}],
            )
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        codes = list(pool.map(lambda _: racer(), range(5)))

    successes = [c for c in codes if c is None]
    failures = [c for c in codes if c is not None]
    assert len(successes) >= 1, f"expected at least one racer to succeed, got codes={codes}"
    assert all(c == "ValidationException" for c in failures), f"unexpected losing codes: {failures}"

    final = _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn),
        lambda r: r["Status"] not in ("UPDATING_LOCATIONS",),
        timeout_s=600.0,
        interval_s=15.0,
    )
    matching = [location_state for location_state in final["LocationStates"] if location_state["LocationName"] == secondary]
    assert len(matching) == 1, (
        f"expected exactly one LocationState for {secondary!r} despite {len(successes)} of "
        f"{len(codes)} concurrent AddStreamGroupLocations calls being admitted, got {len(matching)}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
