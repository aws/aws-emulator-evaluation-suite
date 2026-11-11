"""stop-otel-enrichment-noop-when-already-stopped."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-otel-enrichment-noop-when-already-stopped"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """Calling StopOTelEnrichment while account-level OTel enrichment is already
    Stopped succeeds as a no-op (does not raise) and GetOTelEnrichment continues to
    report Stopped."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]

    def _restore() -> None:
        # StartOTelEnrichment is idempotent and has no not-found case, so any error raises.
        if original_status == "Running":
            cw.start_otel_enrichment()

    ctx.on_cleanup(_restore)

    # setup (not asserted): drive enrichment to Stopped
    try:
        cw.stop_otel_enrichment()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDeniedException", "AccessDenied"):
            raise AssertionError(
                f"StopOTelEnrichment denied ({code}) in this environment - the "
                "caller's IAM permissions are not set up for this check to exercise "
                "the toggle"
            )
        raise

    _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda status: status == "Stopped",
        timeout_s=30,
        interval_s=2,
    )

    # calling stop again while already Stopped must not raise
    cw.stop_otel_enrichment()

    status_after_redundant_call = cw.get_otel_enrichment()["Status"]
    assert status_after_redundant_call == "Stopped", (
        "a redundant StopOTelEnrichment call while already Stopped changed Status to "
        f"{status_after_redundant_call!r}, expected it to remain 'Stopped'"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s, last value: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
