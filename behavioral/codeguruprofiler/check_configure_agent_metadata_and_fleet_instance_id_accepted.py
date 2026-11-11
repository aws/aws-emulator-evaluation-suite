"""configure-agent-metadata-and-fleet-instance-id-accepted."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "configure-agent-metadata-and-fleet-instance-id-accepted"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigureAgent with a fleetInstanceId and metadata returns shouldProfile true, a positive periodInSeconds
    and non-empty agentParameters, and DescribeProfilingGroup then reports latestAgentOrchestratedAt.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=str(uuid.uuid4()),
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"team": "sim2real", "check": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    baseline = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert "latestAgentOrchestratedAt" not in baseline.get("profilingStatus", {}), (
        f"expected no orchestration timestamp before any ConfigureAgent call, "
        f"got {baseline.get('profilingStatus')!r}"
    )

    # AgentId is one of the documented valid metadata keys (ComputePlatform | AgentId |
    # AwsRequestId | ExecutionEnvironment | LambdaFunctionArn | LambdaMemoryLimitInMB |
    # LambdaRemainingTimeInMilliseconds | LambdaTimeGapBetweenInvokesInMilliseconds |
    # LambdaPreviousExecutionTimeInMilliseconds).
    resp = cgp.configure_agent(
        profilingGroupName=name,
        fleetInstanceId="i-0123456789abcdef0",
        metadata={"AgentId": "sim2real-agent-1"},
    )
    configuration = resp["configuration"]
    assert configuration["shouldProfile"] is True, (
        f"expected shouldProfile True for a profiling-enabled group, got {configuration!r}"
    )
    assert isinstance(configuration["periodInSeconds"], int), (
        f"expected periodInSeconds to be an int, got {configuration['periodInSeconds']!r}"
    )
    assert configuration["periodInSeconds"] > 0, (
        f"expected a positive periodInSeconds, got {configuration['periodInSeconds']!r}"
    )
    agent_parameters = configuration.get("agentParameters")
    assert isinstance(agent_parameters, dict) and agent_parameters, (
        f"expected a non-empty agentParameters map in the AgentConfiguration, "
        f"got {agent_parameters!r}"
    )

    # Independent read at the destination: the accepted ConfigureAgent call must be
    # observable outside its own response, via the profiling group's orchestration status.
    described = _poll_until(
        lambda: cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"],
        lambda pg: "latestAgentOrchestratedAt" in pg.get("profilingStatus", {}),
    )
    assert described["profilingStatus"]["latestAgentOrchestratedAt"] is not None, (
        "expected DescribeProfilingGroup to observe the accepted ConfigureAgent call "
        "via a set latestAgentOrchestratedAt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
