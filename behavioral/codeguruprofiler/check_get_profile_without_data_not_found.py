"""get-profile-without-data-not-found."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-profile-without-data-not-found"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetProfile on a new profiling group fails with ResourceNotFoundException 'No profiles found for the
    requested time range!'; after PostAgentProfile sets latestAgentProfileReportedAt, GetProfile for that
    window still answers the same refusal.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=5)
    # Only 2 of {startTime, endTime, period} may be specified together; specifying
    # all 3 is a ValidationException distinct from the "no data" ResourceNotFoundException.
    code, message = _error_code(
        lambda: cgp.get_profile(profilingGroupName=name, startTime=start, endTime=end)
    )
    assert code == "ResourceNotFoundException", (code, message)
    assert message == "No profiles found for the requested time range!", message

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described.get("profilingStatus", {}).get("latestAgentProfileReportedAt") is None, (
        "expected no agent profile ever reported before any PostAgentProfile call",
        described.get("profilingStatus"),
    )

    now_ms = int(time.time() * 1000)
    cgp.post_agent_profile(
        profilingGroupName=name,
        agentProfile=json.dumps(
            {
                "start": now_ms - 60_000,
                "end": now_ms,
                "callgraph": {"frameId": "ALL", "runnableCount": 1, "children": {}},
            }
        ).encode(),
        contentType="application/json",
    )

    after = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    reported_at = after.get("profilingStatus", {}).get("latestAgentProfileReportedAt")
    assert reported_at is not None, (
        "PostAgentProfile succeeded but did not update latestAgentProfileReportedAt",
        after.get("profilingStatus"),
    )

    end2 = datetime.now(timezone.utc)
    start2 = end2 - timedelta(minutes=5)
    code2, message2 = _error_code(
        lambda: cgp.get_profile(profilingGroupName=name, startTime=start2, endTime=end2)
    )
    assert code2 == "ResourceNotFoundException", (
        "expected the just-submitted data to still be unaggregated",
        code2,
        message2,
    )
    assert message2 == "No profiles found for the requested time range!", message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
