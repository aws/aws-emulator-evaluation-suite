"""concurrent-create-monitor-same-name-exactly-one-succeeds."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-monitor-same-name-exactly-one-succeeds"
GROUP = "concurrency"
SERVICES = ["internetmonitor"]


def _safe_delete_monitor(im, name, timeout_s=60.0):
    """DeleteMonitor requires the monitor be INACTIVE first; transition it, then delete."""
    try:
        im.update_monitor(MonitorName=name, Status="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = im.get_monitor(MonitorName=name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status == "INACTIVE":
            break
        time.sleep(2.0)
    im.delete_monitor(MonitorName=name)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateMonitor calls with the same name either succeed with one shared Arn or fail
    with ConflictException, the monitor reaches ACTIVE, and exactly one monitor carries that
    name."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-race-")
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))

    def attempt(_i):
        try:
            resp = im.create_monitor(
                MonitorName=name, TrafficPercentageToMonitor=100, Tags={"team": "network-health"}
            )
            return ("ok", resp.get("Arn"))
        except Exception as err:  # noqa: BLE001 - classify below
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            return ("err", code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, range(6)))

    successes = [r for r in results if r[0] == "ok"]
    conflicts = [r for r in results if r[0] == "err" and r[1] == "ConflictException"]

    assert len(successes) >= 1, f"expected at least 1 successful CreateMonitor, got: {results}"
    assert len(successes) + len(conflicts) == len(results), (
        f"unexpected non-conflict error among racers: {results}"
    )
    # Every successful racer must have been handed the SAME underlying resource (idempotent
    # convergence), not distinct monitors under one name.
    arns = {arn for _, arn in successes}
    assert len(arns) == 1, f"racers converged on different Arns, indicating duplicate resources: {arns}"

    # Namespace ends up with exactly one monitor under this name.
    deadline = time.monotonic() + 60.0
    status = None
    while time.monotonic() < deadline:
        status = im.get_monitor(MonitorName=name)["Status"]
        if status == "ACTIVE":
            break
        time.sleep(2.0)
    assert status == "ACTIVE", f"expected monitor {name} to reach ACTIVE within 60s, last status={status}"

    matching = [m for m in im.list_monitors().get("Monitors", []) if m["MonitorName"] == name]
    assert len(matching) == 1, f"expected exactly one monitor named {name}, found {len(matching)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
