"""configure-agent-fleet-instance-id-too-long-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configure-agent-fleet-instance-id-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfigureAgent rejects a fleetInstanceId over 255 characters with ValidationException and its exact
    message, leaving the group's latestAgentOrchestratedAt unset, while a valid fleetInstanceId sets it.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real-test"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    before = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    before_ts = before.get("profilingStatus", {}).get("latestAgentOrchestratedAt")
    assert before_ts is None, f"expected no orchestration timestamp before any ConfigureAgent call, got {before_ts!r}"

    too_long_id = "i-" + ("0" * 300)
    code, message = _error_code(
        lambda: cgp.configure_agent(profilingGroupName=name, fleetInstanceId=too_long_id)
    )
    assert code == "ValidationException", f"expected ValidationException for a {len(too_long_id)}-char fleetInstanceId, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{too_long_id}' at 'fleetInstanceId' failed to "
        "satisfy constraint: Member must have length less than or equal to 255"
    )
    assert message == expected_message, (message, expected_message)

    # Effect absent: the rejected call did not orchestrate anything.
    after_invalid = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    after_invalid_ts = after_invalid.get("profilingStatus", {}).get("latestAgentOrchestratedAt")
    assert after_invalid_ts is None, f"expected the rejected ConfigureAgent call to leave the orchestration timestamp unset, got {after_invalid_ts!r}"

    # Positive control: a valid fleetInstanceId succeeds and does update it.
    cgp.configure_agent(profilingGroupName=name, fleetInstanceId="i-0123456789abcdef0")
    described = _poll_until(
        lambda: cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"],
        lambda g: g.get("profilingStatus", {}).get("latestAgentOrchestratedAt") is not None,
        timeout_s=60.0,
    )
    final_ts = described["profilingStatus"]["latestAgentOrchestratedAt"]
    assert final_ts is not None, "expected a valid fleetInstanceId to set the orchestration timestamp"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
