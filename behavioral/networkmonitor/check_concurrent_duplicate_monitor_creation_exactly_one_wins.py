"""concurrent-duplicate-monitor-creation-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-duplicate-monitor-creation-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When N racers concurrently CreateMonitor with the identical monitorName, exactly one
    request succeeds and every other racer receives ConflictException -- no duplicate resource
    is silently created.
    """
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nwm-mon-")
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))

    def _attempt(_i):
        try:
            nm.create_monitor(monitorName=name, aggregationPeriod=30, tags={"sim2real": "audit"})
            return ("ok", None)
        except Exception as e:  # noqa: BLE001
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("error", e.response["Error"]["Code"])
            return ("error", "unknown")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_attempt, range(8)))

    successes = [r for r in results if r[0] == "ok"]
    conflicts = [r for r in results if r[0] == "error" and r[1] == "ConflictException"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(conflicts) == 7, f"expected exactly 7 ConflictException losers, got {results}"

    listed = nm.list_monitors()["monitors"]
    assert sum(1 for m in listed if m["monitorName"] == name) == 1, "no duplicate monitor should exist"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
