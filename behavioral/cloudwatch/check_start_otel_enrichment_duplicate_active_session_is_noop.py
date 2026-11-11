"""start-otel-enrichment-duplicate-active-session-is-noop."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-otel-enrichment-duplicate-active-session-is-noop"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """A second StartOTelEnrichment while the account's status is Running succeeds and leaves
    GetOTelEnrichment at Running: the operation sets the state, it does not toggle it."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]
    ctx.on_cleanup(lambda: _restore_status(ctx, original_status))

    cw.start_otel_enrichment()
    running_status = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda status: status == "Running",
        timeout_s=60,
    )
    assert running_status == "Running"

    # Duplicate call while a session is already active: must be a genuine no-op,
    # not silently treated as a restart that resets/flips the state to Stopped.
    cw.start_otel_enrichment()
    status_after_duplicate_call = cw.get_otel_enrichment()["Status"]
    assert status_after_duplicate_call == "Running", (
        f"a duplicate StartOTelEnrichment call changed Status to "
        f"{status_after_duplicate_call!r} instead of leaving it Running"
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
