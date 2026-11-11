"""logging-configuration-reaches-active-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logging-configuration-reaches-active-state"
GROUP = "state-machine"
SERVICES = ["ivschat"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLoggingConfiguration against a real CloudWatch Logs group transitions to the
    ACTIVE state (per documented CREATING -> ACTIVE state machine) and GetLoggingConfiguration
    reflects the exact destination configuration once active."""
    logs = ctx.client("logs")
    ivschat = ctx.client("ivschat")

    log_group = ctx.unique_name("/sim2real/ivschat-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    name = ctx.unique_name("sim2real-ivschat-logcfg")
    created = ivschat.create_logging_configuration(
        name=name,
        destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group}},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_logging_configuration(identifier=arn))

    final = _poll_until(
        lambda: ivschat.get_logging_configuration(identifier=arn),
        lambda r: r["state"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["state"] == "ACTIVE", f"unexpected terminal state: {final['state']}"
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    got_log_group = final["destinationConfiguration"]["cloudWatchLogs"]["logGroupName"]
    assert got_log_group == log_group, f"expected log group {log_group!r}, got {got_log_group!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
