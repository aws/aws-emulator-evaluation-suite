"""post-agent-profile-nonexistent-group-not-found-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "post-agent-profile-nonexistent-group-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _agent_profile(now_ms: int) -> bytes:
    return json.dumps(
        {
            "start": now_ms - 60_000,
            "end": now_ms,
            "callgraph": {"frameId": "ALL", "runnableCount": 1, "children": {}},
        }
    ).encode()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PostAgentProfile against a profiling group that was never created fails with
    ResourceNotFoundException naming the account and the missing group, while the identical
    submission against a real profiling group succeeds and registers.
    """
    cgp = ctx.client("codeguruprofiler")
    missing_name = ctx.unique_name("sim2real-behav-cgp-missing-")

    err = _error(
        lambda: cgp.post_agent_profile(
            profilingGroupName=missing_name,
            agentProfile=_agent_profile(int(time.time() * 1000)),
            contentType="application/json",
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a profiling group that was never created, "
        f"got {err['Code']!r}"
    )
    expected_message = (
        f"No profiling group found in account {ctx.account} with name {missing_name}."
    )
    assert err["Message"] == expected_message, (err["Message"], expected_message)

    # positive control: the identical submission against a real profiling group succeeds
    # and registers as the group's latest reported profile.
    real_name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=real_name, agentOrchestrationConfig={"profilingEnabled": True}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=real_name))

    before = cgp.describe_profiling_group(profilingGroupName=real_name)["profilingGroup"]
    assert before.get("profilingStatus", {}).get("latestAgentProfileReportedAt") is None, (
        "expected no agent profile ever reported before any PostAgentProfile call",
        before.get("profilingStatus"),
    )

    cgp.post_agent_profile(
        profilingGroupName=real_name,
        agentProfile=_agent_profile(int(time.time() * 1000)),
        contentType="application/json",
    )

    after = cgp.describe_profiling_group(profilingGroupName=real_name)["profilingGroup"]
    reported_at = after.get("profilingStatus", {}).get("latestAgentProfileReportedAt")
    assert reported_at is not None, (
        "the positive control's PostAgentProfile succeeded but did not update "
        "latestAgentProfileReportedAt",
        after.get("profilingStatus"),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
