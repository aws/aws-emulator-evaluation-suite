"""stream-group-lifecycle-reaches-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-group-lifecycle-reaches-active"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created stream group transitions ACTIVATING -> ACTIVE once Amazon GameLift
    Streams finishes provisioning capacity for its location."""
    gl = ctx.client("gameliftstreams")
    try:
        created = gl.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": ctx.region, "MaximumCapacity": 2}],
            Tags={"sim2real-check": CHECK},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no Gen4n GPU quota in this Region ({e}); GameLift Streams GPU "
                "quotas default to 0 and must be explicitly requested -- cannot provision any "
                "stream group capacity in this sandbox"
            )
        raise
    arn = created["Arn"]
    ctx.on_cleanup(lambda: gl.delete_stream_group(Identifier=arn))
    assert created["Status"] == "ACTIVATING", f"expected ACTIVATING on create, got {created['Status']!r}"

    final = _poll_until(
        lambda: gl.get_stream_group(Identifier=arn),
        lambda r: r["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=260.0,
        interval_s=15.0,
    )
    assert final["Status"] == "ACTIVE", f"expected ACTIVE, got {final['Status']} ({final.get('StatusReason')})"
    assert len(final["LocationStates"]) == 1, (
        f"expected exactly 1 location state for the single requested location, got "
        f"{len(final['LocationStates'])}: {final['LocationStates']!r}"
    )
    location = final["LocationStates"][0]
    assert location["LocationName"] == ctx.region, (
        f"expected the active location to be the requested region {ctx.region!r}, got "
        f"{location['LocationName']!r}"
    )
    assert location["Status"] == "ACTIVE", f"expected location {ctx.region!r} ACTIVE, got {location['Status']!r}"


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
