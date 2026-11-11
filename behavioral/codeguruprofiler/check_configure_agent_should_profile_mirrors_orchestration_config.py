"""configure-agent-should-profile-mirrors-orchestration-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "configure-agent-should-profile-mirrors-orchestration-config"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigureAgent.shouldProfile mirrors the profiling group's current
    agentOrchestrationConfig.profilingEnabled, in both directions."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    config = cgp.configure_agent(profilingGroupName=name)["configuration"]
    assert config["shouldProfile"] is True, (
        f"expected shouldProfile=True when profilingEnabled=True, got {config['shouldProfile']!r}"
    )
    assert config["periodInSeconds"] > 0, (
        f"expected periodInSeconds > 0, got {config['periodInSeconds']!r}"
    )

    cgp.update_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": False},
    )
    config = _poll_until(
        lambda: cgp.configure_agent(profilingGroupName=name)["configuration"],
        lambda c: c["shouldProfile"] is False,
        timeout_s=30.0,
    )
    assert config["shouldProfile"] is False, (
        f"expected shouldProfile=False after disabling profiling, got {config['shouldProfile']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
