"""otel-enrichment-idempotent-start-stop."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "otel-enrichment-idempotent-start-stop"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """Calling StartOTelEnrichment while already Running (and StopOTelEnrichment while already
    Stopped) is idempotent: no error, and GetOTelEnrichment.Status is unchanged."""
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]
    ctx.on_cleanup(lambda: _restore(cw, original_status))

    # Drive to Running, then call Start again while already Running -> idempotent no-op.
    cw.start_otel_enrichment()
    status = _poll_until(lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Running", timeout_s=30.0)
    assert status == "Running", f"expected Running after StartOTelEnrichment, got {status}"

    cw.start_otel_enrichment()
    _assert_stays(
        lambda: cw.get_otel_enrichment()["Status"], "Running", timeout_s=10.0, interval_s=2.0,
        message="a second StartOTelEnrichment while Running changed the status",
    )

    # Drive to Stopped, then call Stop again while already Stopped -> idempotent no-op.
    cw.stop_otel_enrichment()
    status = _poll_until(lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Stopped", timeout_s=30.0)
    assert status == "Stopped", f"expected Stopped after StopOTelEnrichment, got {status}"

    cw.stop_otel_enrichment()
    _assert_stays(
        lambda: cw.get_otel_enrichment()["Status"], "Stopped", timeout_s=10.0, interval_s=2.0,
        message="a second StopOTelEnrichment while Stopped changed the status",
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {value!r}")


def _assert_stays(probe, expected, *, timeout_s=10.0, interval_s=2.0, message=""):
    """Repeatedly samples probe() across a bounded window and asserts it never deviates from
    expected -- used in place of a single bare sleep+check to observe steady-state behavior."""
    deadline = time.monotonic() + timeout_s
    sampled = False
    while time.monotonic() < deadline:
        value = probe()
        sampled = True
        if value != expected:
            raise AssertionError(f"{message or 'value changed unexpectedly'} (got {value!r})")
        time.sleep(interval_s)
    if not sampled:
        # timeout_s smaller than one interval: still take at least one sample.
        value = probe()
        if value != expected:
            raise AssertionError(f"{message or 'value changed unexpectedly'} (got {value!r})")


def _restore(cw, original_status) -> None:
    """Return the account to its original status; both calls are idempotent, so any error raises."""
    if original_status == "Running":
        cw.start_otel_enrichment()
    else:
        cw.stop_otel_enrichment()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
