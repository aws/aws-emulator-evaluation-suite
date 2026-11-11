"""otel-enrichment-start-stop-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "otel-enrichment-start-stop-state-transition"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """StartOTelEnrichment/StopOTelEnrichment drive GetOTelEnrichment.Status between Running/Stopped."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment().get("Status")

    def _restore() -> None:
        # Both calls are idempotent and have no not-found case, so any error raises.
        if original_status == "Running":
            cw.start_otel_enrichment()
        elif original_status == "Stopped":
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    cw.start_otel_enrichment()
    status = _poll_for(lambda: cw.get_otel_enrichment().get("Status"), "Running", timeout_s=30, interval_s=2)
    assert status == "Running", f"expected Status=Running after StartOTelEnrichment, got {status!r}"

    cw.stop_otel_enrichment()
    status = _poll_for(lambda: cw.get_otel_enrichment().get("Status"), "Stopped", timeout_s=30, interval_s=2)
    assert status == "Stopped", f"expected Status=Stopped after StopOTelEnrichment, got {status!r}"


def _poll_for(probe, expected, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last == expected:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
