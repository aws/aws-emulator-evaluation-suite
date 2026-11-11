"""otel-enrichment-status-visible-immediately-after-start-stop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "otel-enrichment-status-visible-immediately-after-start-stop"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """GetOTelEnrichment status reflects Start/Stop calls synchronously, without
    a lag window."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]

    def _restore():
        if original_status == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    cw.start_otel_enrichment()
    status = cw.get_otel_enrichment()["Status"]
    assert status == "Running", f"expected Running immediately after StartOTelEnrichment, got {status!r}"

    cw.stop_otel_enrichment()
    status = cw.get_otel_enrichment()["Status"]
    assert status == "Stopped", f"expected Stopped immediately after StopOTelEnrichment, got {status!r}"

    cw.start_otel_enrichment()
    status = cw.get_otel_enrichment()["Status"]
    assert status == "Running", f"expected Running immediately after second StartOTelEnrichment, got {status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
