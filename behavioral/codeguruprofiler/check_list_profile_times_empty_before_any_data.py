"""list-profile-times-empty-before-any-data."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-profile-times-empty-before-any-data"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfileTimes for a valid time range on a profiling group that has never received
    any agent profile data succeeds (it is not an error) and returns an empty profileTimes
    list."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=str(uuid.uuid4()),
        tags={"env": "sim2real"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)

    resp = cgp.list_profile_times(
        profilingGroupName=name, startTime=start, endTime=end, period="PT1H"
    )
    assert resp["profileTimes"] == [], (
        f"a profiling group with no agent data yet returned "
        f'profileTimes={resp["profileTimes"]!r} for a valid range, expected an empty list'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
