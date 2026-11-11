"""update-logging-configuration-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-logging-configuration-state-transition"
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
    """UpdateLoggingConfiguration on an ACTIVE config drives it through the documented
    ACTIVE -> UPDATING -> ACTIVE state machine and the new name/destination persist."""
    logs = ctx.client("logs")
    ivschat = ctx.client("ivschat")

    log_group_a = ctx.unique_name("/sim2real/ivschat-a-")
    log_group_b = ctx.unique_name("/sim2real/ivschat-b-")
    resource_tags = {"sim2real-check": CHECK}
    logs.create_log_group(logGroupName=log_group_a, tags=resource_tags)
    logs.create_log_group(logGroupName=log_group_b, tags=resource_tags)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_a))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_b))

    name = ctx.unique_name("sim2real-ivschat-logcfg")
    created = ivschat.create_logging_configuration(
        name=name,
        destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group_a}},
        tags=resource_tags,
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_logging_configuration(identifier=arn))
    _poll_until(
        lambda: ivschat.get_logging_configuration(identifier=arn),
        lambda r: r["state"] == "ACTIVE",
        timeout_s=60.0,
    )

    new_name = ctx.unique_name("sim2real-ivschat-logcfg-renamed")
    ivschat.update_logging_configuration(
        identifier=arn,
        name=new_name,
        destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group_b}},
    )

    final = _poll_until(
        lambda: ivschat.get_logging_configuration(identifier=arn),
        lambda r: r["state"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["state"] == "ACTIVE", f"unexpected terminal state: {final['state']}"
    assert final["name"] == new_name, f"expected name={new_name!r}, got {final['name']!r}"
    got_log_group = final["destinationConfiguration"]["cloudWatchLogs"]["logGroupName"]
    assert got_log_group == log_group_b, (
        f"expected destination log group {log_group_b!r}, got {got_log_group!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
