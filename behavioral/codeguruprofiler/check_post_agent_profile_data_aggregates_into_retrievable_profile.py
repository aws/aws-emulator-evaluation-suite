"""post-agent-profile-data-aggregates-into-retrievable-profile."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "post-agent-profile-data-aggregates-into-retrievable-profile"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


def _poll_until_aggregated(cgp, name: str, *, budget_s: float = 900.0, interval_s: float = 20.0):
    """The profile dict (JSON) for the latest aggregated 5-minute profile, once CodeGuru Profiler
    has finished aggregating posted agent data into it.
    """
    deadline = time.monotonic() + budget_s
    while True:
        try:
            resp = cgp.get_profile(
                profilingGroupName=name, period="PT5M", accept="application/json"
            )
            body = resp["profile"].read()
            if resp.get("contentEncoding") == "gzip":
                body = gzip.decompress(body)
            return json.loads(body)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if time.monotonic() > deadline:
            raise AssertionError(f"no aggregated profile appeared within {budget_s}s")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Agent profile data PostAgentProfile submits for a closed 5-minute window becomes, once
    CodeGuru Profiler finishes aggregating it, a retrievable profile whose window and reported-agent
    count GetProfile and ListProfileTimes both reflect — not merely a 200 on the submission.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name, agentOrchestrationConfig={"profilingEnabled": True}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    fleet_instance_id = ctx.unique_name("sim2real-behav-cgp-fleet-")
    agent_config = cgp.configure_agent(
        profilingGroupName=name, fleetInstanceId=fleet_instance_id
    )["configuration"]
    assert agent_config["shouldProfile"] is True, (
        f"expected a fresh profiling group to tell its agent to profile, got {agent_config!r}"
    )

    period_ms = 5 * 60 * 1000
    now_ms = int(time.time() * 1000)
    window_end_ms = (now_ms // period_ms) * period_ms
    window_start_ms = window_end_ms - period_ms
    window_start = datetime.fromtimestamp(window_start_ms / 1000, tz=timezone.utc)
    window_end = datetime.fromtimestamp(window_end_ms / 1000, tz=timezone.utc)

    agent_profile = json.dumps(
        {
            "start": window_start_ms,
            "end": window_end_ms,
            "callgraph": {"frameId": "ALL", "runnableCount": 1000, "children": {}},
        }
    ).encode()
    cgp.post_agent_profile(
        profilingGroupName=name, agentProfile=agent_profile, contentType="application/json"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    reported_at = described.get("profilingStatus", {}).get("latestAgentProfileReportedAt")
    assert reported_at is not None, (
        "PostAgentProfile succeeded but did not update latestAgentProfileReportedAt, "
        f"got profilingStatus {described.get('profilingStatus')!r}"
    )

    def _list_times():
        return cgp.list_profile_times(
            profilingGroupName=name,
            startTime=window_start - timedelta(minutes=1),
            endTime=window_end + timedelta(minutes=1),
            period="PT5M",
        )["profileTimes"]

    profile = _poll_until_aggregated(cgp, name)

    expected_start = window_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert profile["start"] == expected_start, (
        f"expected the aggregated profile to start at {expected_start!r}, got {profile['start']!r}"
    )
    expected_end = window_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert profile["end"] == expected_end, (
        f"expected the aggregated profile to end at {expected_end!r}, got {profile['end']!r}"
    )
    num_reported_agents = profile["aggregatedMetadata"]["numReportedAgents"]
    assert num_reported_agents == 1, (
        f"exactly one agent ({fleet_instance_id}) posted into this window, "
        f"expected numReportedAgents == 1, got {num_reported_agents!r}"
    )

    times = _list_times()
    assert times == [{"start": window_start}], (
        f"expected ListProfileTimes to list exactly the aggregated window {window_start!r}, "
        f"got {times!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
