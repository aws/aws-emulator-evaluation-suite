"""start-otel-enrichment-repeat-call-idempotent."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-otel-enrichment-repeat-call-idempotent"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """Repeating StartOTelEnrichment while Running, and StopOTelEnrichment while Stopped, succeeds
    and GetOTelEnrichment reads Running and Stopped respectively: neither operation has a
    wrong-state error."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]

    def _restore() -> None:
        if original_status == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    # Drive to Running, then call Start again while already Running.
    cw.start_otel_enrichment()
    _poll_status(cw, "Running")
    cw.start_otel_enrichment()  # must not raise a wrong-state conflict
    status_after_repeat_start = cw.get_otel_enrichment()["Status"]
    assert status_after_repeat_start == "Running", (
        f"a repeated StartOTelEnrichment call while already Running changed "
        f"Status to {status_after_repeat_start!r} instead of leaving it Running"
    )

    # Drive to Stopped, then call Stop again while already Stopped.
    cw.stop_otel_enrichment()
    _poll_status(cw, "Stopped")
    cw.stop_otel_enrichment()  # must not raise a wrong-state conflict
    status_after_repeat_stop = cw.get_otel_enrichment()["Status"]
    assert status_after_repeat_stop == "Stopped", (
        f"a repeated StopOTelEnrichment call while already Stopped changed "
        f"Status to {status_after_repeat_stop!r} instead of leaving it Stopped"
    )


def _poll_status(cw, expected: str, timeout_s: float = 30.0, interval_s: float = 1.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_otel_enrichment()["Status"]
        if last == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"OTelEnrichmentStatus never reached {expected!r}, last was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
