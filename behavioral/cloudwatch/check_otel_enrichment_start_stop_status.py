"""otel-enrichment-start-stop-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "otel-enrichment-start-stop-status"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """StartOTelEnrichment flips account status to Running; StopOTelEnrichment flips it back to Stopped."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]

    def _restore():
        # Both calls are idempotent and have no not-found case, so any error raises.
        if original_status == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    cw.start_otel_enrichment()

    running_status = _poll_until(lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Running", timeout_s=30.0)
    assert running_status == "Running", f"expected Running after StartOTelEnrichment, got {running_status}"

    cw.stop_otel_enrichment()

    stopped_status = _poll_until(lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Stopped", timeout_s=30.0)
    assert stopped_status == "Stopped", f"expected Stopped after StopOTelEnrichment, got {stopped_status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
