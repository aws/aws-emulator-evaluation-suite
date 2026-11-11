"""get-otel-enrichment-start-stop-toggle-reports-running-and-stopped."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-otel-enrichment-start-stop-toggle-reports-running-and-stopped"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """StartOTelEnrichment and StopOTelEnrichment drive GetOTelEnrichment.Status to Running and
    Stopped; the account-wide toggle is restored to its original setting afterwards.
    """
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]
    assert original_status in ("Running", "Stopped"), (
        f"GetOTelEnrichment returned an unmodelled Status: {original_status!r}"
    )

    def _restore():
        if original_status == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    cw.start_otel_enrichment()
    started_status = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda status: status == "Running",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert started_status == "Running", (
        f"StartOTelEnrichment did not drive GetOTelEnrichment.Status to Running "
        f"within 60s; last observed {started_status!r}"
    )

    cw.stop_otel_enrichment()
    stopped_status = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda status: status == "Stopped",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert stopped_status == "Stopped", (
        f"StopOTelEnrichment did not drive GetOTelEnrichment.Status to Stopped "
        f"within 60s; last observed {stopped_status!r}"
    )


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
