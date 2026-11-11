"""add-stream-group-location-duplicate-is-an-idempotent-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-stream-group-location-duplicate-is-an-idempotent-no-op"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddStreamGroupLocations re-adding a location the stream group already has at the
    same capacity is accepted idempotently -- no error, no duplicate LocationState, group
    stays ACTIVE; adding a genuinely new location succeeds and appears in LocationStates."""
    gl = ctx.client("gameliftstreams")
    primary = ctx.region
    # GameLiftStreams stream groups only accept locations from its supported streaming
    # location list (see the service's "Regions, quotas, and limitations" guide), not an
    # arbitrary AWS Region -- these three are always on that list.
    secondary = next(loc for loc in ("us-east-1", "us-west-2", "eu-west-1") if loc != primary)

    try:
        sg = gl.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": primary, "MaximumCapacity": 2}],
            Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
    initial = _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn),
        lambda r: r["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    # positive control: the group must actually reach ACTIVE, not merely stop transitioning --
    # ACTIVE_WITH_ERRORS/ERROR are also terminal and would otherwise pass silently.
    assert initial["Status"] == "ACTIVE", f"positive control: expected ACTIVE, got {initial['Status']!r}"

    # measured against real AWS: re-adding the SAME location at the SAME capacity is
    # accepted idempotently -- HTTP 200, no ValidationException -- and the re-added
    # location's own state comes back unchanged in the very same response.
    readd_response = gl.add_stream_group_locations(
        Identifier=sg_arn,
        LocationConfigurations=[{"LocationName": primary, "MaximumCapacity": 2}],
    )
    readded = next(
        (loc for loc in readd_response["Locations"] if loc["LocationName"] == primary), None
    )
    assert readded is not None, (
        f"expected {primary!r} in the AddStreamGroupLocations response, "
        f"got {readd_response['Locations']!r}"
    )
    assert readded["Status"] == "ACTIVE", f"expected the re-added location to stay ACTIVE, got {readded['Status']!r}"

    unchanged = gl.get_stream_group(Identifier=sg_arn)
    assert unchanged["Status"] == "ACTIVE", (
        f"expected the stream group to stay ACTIVE after the idempotent re-add, got {unchanged['Status']!r}"
    )
    matching_primary = [
        location_state for location_state in unchanged["LocationStates"] if location_state["LocationName"] == primary
    ]
    assert len(matching_primary) == 1, (
        f"expected exactly one LocationState for {primary!r} after the idempotent re-add, "
        f"got {len(matching_primary)}: {unchanged['LocationStates']!r}"
    )

    gl.add_stream_group_locations(
        Identifier=sg_arn,
        LocationConfigurations=[{"LocationName": secondary, "MaximumCapacity": 2}],
    )

    def _secondary_location(r):
        return next((loc for loc in r["LocationStates"] if loc["LocationName"] == secondary), None)

    # measured against real AWS: the stream group's own Status can leave UPDATING_LOCATIONS
    # before a just-added location's OWN LocationState finishes activating, so the terminal
    # read is the location's status, never the group's.
    after = _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn),
        lambda r: (loc := _secondary_location(r)) is not None and loc["Status"] not in ("ACTIVATING",),
        timeout_s=600.0,
        interval_s=15.0,
    )
    added = _secondary_location(after)
    names = {location_state["LocationName"] for location_state in after["LocationStates"]}
    assert added is not None, f"expected {secondary!r} to be added, locations={names}"
    assert added["Status"] == "ACTIVE", f"expected {secondary!r} to reach ACTIVE, got {added['Status']!r}"


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
