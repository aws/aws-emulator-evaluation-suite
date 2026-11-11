"""get-otel-enrichment-reflects-server-managed-state."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "get-otel-enrichment-reflects-server-managed-state"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment", "resource:account-singleton:config-service-linked-recorder", "resource:account-singleton:observabilityadmin-telemetry-enrichment")
def run(ctx) -> None:
    """GetOTelEnrichment always reflects the server-enforced enrichment state: repeated reads are
    stable, unrelated CloudWatch mutations never change it, and it only flips via Start/Stop."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "get_otel_enrichment"):
        raise AssertionError("cloudwatch client does not support OTel enrichment APIs")

    baseline = cw.get_otel_enrichment()["Status"]
    ctx.on_cleanup(lambda: _restore_otel_status(cw, baseline))

    # 1. Repeated reads with no mutation in between must be perfectly stable.
    for _ in range(3):
        repeated = cw.get_otel_enrichment()["Status"]
        assert repeated == baseline, f"expected stable OTel enrichment status {baseline!r}, got {repeated!r}"

    # 2. An unrelated CloudWatch mutation must never move the OTel enrichment status.
    namespace = ctx.unique_name("Sim2RealBehavOtel")
    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": "Unrelated", "Value": 1.0}])
    assert cw.get_otel_enrichment()["Status"] == baseline, (
        "unrelated PutMetricData call changed the OTel enrichment status"
    )

    # 3. It only transitions through explicit Start/Stop calls.
    if baseline == "Stopped":
        _start_otel_with_prereq(ctx, cw, stop_prereq_after=True)
        toggled = _poll_otel_status(ctx, cw, "Running")
        assert toggled == "Running", f"expected Running after StartOTelEnrichment, got {toggled!r}"
        cw.stop_otel_enrichment()
        restored = _poll_otel_status(ctx, cw, "Stopped")
        assert restored == "Stopped", f"expected Stopped after StopOTelEnrichment, got {restored!r}"
    else:
        cw.stop_otel_enrichment()
        toggled = _poll_otel_status(ctx, cw, "Stopped")
        assert toggled == "Stopped", f"expected Stopped after StopOTelEnrichment, got {toggled!r}"
        _start_otel_with_prereq(ctx, cw, stop_prereq_after=False)
        restored = _poll_otel_status(ctx, cw, "Running")
        assert restored == "Running", f"expected Running after StartOTelEnrichment, got {restored!r}"


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


_CLEANUP_BUDGET_S = 900.0


def _deadline(ctx: Any, timeout_s: float) -> float:
    """A poll deadline: timeout_s from now, capped by the runner's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _poll_otel_status(ctx: Any, cw: Any, expected: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = cw.get_otel_enrichment()["Status"]
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"OTel enrichment never reached {expected!r}, last={last!r}")


def _restore_otel_status(cw: Any, baseline: str) -> None:
    """Put the account-wide enrichment status back; it cannot be missing, so any error raises."""
    current = cw.get_otel_enrichment()["Status"]
    if current != baseline:
        if baseline == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()


def _start_otel_with_prereq(ctx: Any, cw: Any, *, stop_prereq_after: bool) -> None:
    """StartOTelEnrichment requires the account to have resource-tags-on-telemetry enabled
    first (observabilityadmin:StartTelemetryEnrichment). Enable it on demand if needed, and
    stop it again in cleanup when stop_prereq_after is set and this check started it."""
    try:
        cw.start_otel_enrichment()
        return
    except ClientError as exc:
        # ValidationException is the documented answer while the prerequisite is missing.
        if exc.response["Error"]["Code"] != "ValidationException":
            raise

    oa = ctx.client("observabilityadmin")
    # A never-started feature reads as ResourceNotFoundException, i.e. not Running.
    try:
        status = oa.get_telemetry_enrichment_status()["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        status = "Stopped"
    if status != "Running":
        oa.start_telemetry_enrichment()
        if stop_prereq_after:
            ctx.on_cleanup(lambda: _stop_prereq(oa))

    deadline = _deadline(ctx, 60.0)
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cw.start_otel_enrichment()
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"StartOTelEnrichment kept failing after enabling its prerequisite: {last_err}")


def _stop_prereq(oa: Any) -> None:
    """Stop the prerequisite this check started, retrying ConflictException (a transition in
    progress) every 2 s to the cleanup deadline; a feature already gone is done."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        try:
            oa.stop_telemetry_enrichment()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
