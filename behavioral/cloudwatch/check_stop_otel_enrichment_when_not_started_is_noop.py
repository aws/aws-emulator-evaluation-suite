"""stop-otel-enrichment-when-not-started-is-noop."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stop-otel-enrichment-when-not-started-is-noop"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """A redundant StopOTelEnrichment while the account's status is Stopped succeeds and leaves
    GetOTelEnrichment at Stopped: the operation sets the state, it does not toggle it."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]
    ctx.on_cleanup(lambda: _restore_status(ctx, original_status))

    cw.stop_otel_enrichment()
    stopped_status = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda status: status == "Stopped",
        timeout_s=60,
    )
    assert stopped_status == "Stopped", (
        f"expected Status Stopped after StopOTelEnrichment, got {stopped_status!r}"
    )

    # Redundant call while already in the target state: must be a genuine no-op,
    # not silently treated as a restart that flips the state back to Running.
    cw.stop_otel_enrichment()
    status_after_redundant_call = cw.get_otel_enrichment()["Status"]
    assert status_after_redundant_call == "Stopped", (
        f"a redundant StopOTelEnrichment call changed Status to "
        f"{status_after_redundant_call!r} instead of leaving it Stopped"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _restore_status(ctx, original_status):
    cw = ctx.client("cloudwatch")
    if original_status == "Running":
        cw.start_otel_enrichment()
    else:
        cw.stop_otel_enrichment()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
