"""configure-agent-reflects-profiling-enabled-toggle."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "configure-agent-reflects-profiling-enabled-toggle"
GROUP = "state-machine"
SERVICES = ["codeguruprofiler"]


def _poll_should_profile(cgp, name, expected, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cgp.configure_agent(profilingGroupName=name)["configuration"]["shouldProfile"]
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"shouldProfile never reached {expected} (last={last})")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProfilingGroup's agentOrchestrationConfig.profilingEnabled is mirrored by
    ConfigureAgent's shouldProfile field, in both directions."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=str(uuid.uuid4()),
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real-test"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    got = _poll_should_profile(cgp, name, True)
    assert got is True, f"shouldProfile after create(profilingEnabled=True): expected True, got {got}"

    cgp.update_profiling_group(
        profilingGroupName=name, agentOrchestrationConfig={"profilingEnabled": False}
    )
    got = _poll_should_profile(cgp, name, False)
    assert got is False, f"shouldProfile after update(profilingEnabled=False): expected False, got {got}"

    cgp.update_profiling_group(
        profilingGroupName=name, agentOrchestrationConfig={"profilingEnabled": True}
    )
    got = _poll_should_profile(cgp, name, True)
    assert got is True, f"shouldProfile after update(profilingEnabled=True): expected True, got {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
