"""otel-enrichment-start-get-stop-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "otel-enrichment-start-get-stop-lifecycle"
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
    """StartOTelEnrichment transitions account status to Running; StopOTelEnrichment reverts it to Stopped."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]

    def _restore():
        if original_status == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    cw.start_otel_enrichment()
    status_after_start = _poll_until_status(cw, "Running", timeout_s=30.0)
    assert status_after_start == "Running", f"expected Running after StartOTelEnrichment, got {status_after_start!r}"

    cw.stop_otel_enrichment()
    status_after_stop = _poll_until_status(cw, "Stopped", timeout_s=30.0)
    assert status_after_stop == "Stopped", f"expected Stopped after StopOTelEnrichment, got {status_after_stop!r}"


def _poll_until_status(cw, expected: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_otel_enrichment()["Status"]
        if last == expected:
            return last
        time.sleep(1)
    raise AssertionError(f"OTelEnrichment status never reached {expected!r}; last observed {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
