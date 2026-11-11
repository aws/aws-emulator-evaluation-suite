"""e2e-room-logging-attach-workflow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-room-logging-attach-workflow"
GROUP = "state"
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
    """UpdateRoom can attach a logging configuration to a room created without one, and
    GetRoom durably reflects the new loggingConfigurationIdentifiers list afterward."""
    logs = ctx.client("logs")
    ivschat = ctx.client("ivschat")

    log_group = ctx.unique_name("/sim2real/ivschat-attach2-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    cfg = ivschat.create_logging_configuration(
        name=ctx.unique_name("sim2real-ivschat-logcfg"),
        destinationConfiguration={"cloudWatchLogs": {"logGroupName": log_group}},
    )
    cfg_arn = cfg["arn"]
    _poll_until(
        lambda: ivschat.get_logging_configuration(identifier=cfg_arn),
        lambda r: r["state"] == "ACTIVE",
        timeout_s=60.0,
    )

    room = ivschat.create_room(name=ctx.unique_name("sim2real-ivschat-room"))
    room_arn = room["arn"]
    assert room.get("loggingConfigurationIdentifiers", []) == [], (
        f"expected a freshly created room to have no logging configurations attached, "
        f"got {room.get('loggingConfigurationIdentifiers')!r}"
    )

    def _cleanup_room_then_cfg():
        ivschat.update_room(identifier=room_arn, loggingConfigurationIdentifiers=[])
        ivschat.delete_room(identifier=room_arn)
        ivschat.delete_logging_configuration(identifier=cfg_arn)

    ctx.on_cleanup(_cleanup_room_then_cfg)

    ivschat.update_room(identifier=room_arn, loggingConfigurationIdentifiers=[cfg_arn])

    got = ivschat.get_room(identifier=room_arn)
    assert got["loggingConfigurationIdentifiers"] == [cfg_arn], (
        f"expected GetRoom to durably reflect the attached logging configuration "
        f"[{cfg_arn!r}], got {got['loggingConfigurationIdentifiers']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
