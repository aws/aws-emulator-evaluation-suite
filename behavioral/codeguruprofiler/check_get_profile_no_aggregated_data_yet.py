"""get-profile-no-aggregated-data-yet."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-profile-no-aggregated-data-yet"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetProfile on a group with no agent data fails with ResourceNotFoundException 'No profiles found for the
    requested time range!' while the group is describable; after PostAgentProfile sets
    latestAgentProfileReportedAt, GetProfile still answers the same refusal.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    cgp.create_profiling_group(
        profilingGroupName=name, agentOrchestrationConfig={"profilingEnabled": True}
    )

    code, message = _error_code(
        lambda: cgp.get_profile(profilingGroupName=name, period="PT5M")
    )
    assert code == "ResourceNotFoundException", (code, message)
    assert message == "No profiles found for the requested time range!", message

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["name"] == name
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

    code2, message2 = _error_code(
        lambda: cgp.get_profile(profilingGroupName=name, period="PT5M")
    )
    assert code2 == "ResourceNotFoundException", (
        "expected the just-submitted data to still be unaggregated",
        code2,
        message2,
    )
    assert message2 == "No profiles found for the requested time range!", message2


def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a rejection, but the call SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
