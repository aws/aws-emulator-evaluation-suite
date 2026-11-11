"""otel-enrichment-start-stop-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "otel-enrichment-start-stop-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment", "resource:account-singleton:config-service-linked-recorder", "resource:account-singleton:observabilityadmin-telemetry-enrichment")
def run(ctx) -> None:
    """StartOTelEnrichment transitions enrichment to Running as reflected by GetOTelEnrichment,
    and StopOTelEnrichment transitions it back to Stopped."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "get_otel_enrichment"):
        raise AssertionError("cloudwatch client does not support OTel enrichment APIs")

    baseline = cw.get_otel_enrichment()["Status"]
    ctx.on_cleanup(lambda: _restore_otel_status(cw, baseline))

    if baseline == "Running":
        cw.stop_otel_enrichment()
        _poll_otel_status(cw, "Stopped")

    _start_otel_with_prereq(ctx, cw)
    started = _poll_otel_status(cw, "Running")
    assert started == "Running", f"expected Running after StartOTelEnrichment, got {started!r}"

    cw.stop_otel_enrichment()
    stopped = _poll_otel_status(cw, "Stopped")
    assert stopped == "Stopped", f"expected Stopped after StopOTelEnrichment, got {stopped!r}"


# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402


def _poll_otel_status(cw: Any, expected: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_otel_enrichment()["Status"]
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"OTel enrichment never reached {expected!r}, last={last!r}")


def _restore_otel_status(cw: Any, baseline: str) -> None:
    """Return the account to its baseline status; the toggle has no not-found case, so any error raises."""
    current = cw.get_otel_enrichment()["Status"]
    if current != baseline:
        if baseline == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()


def _start_otel_with_prereq(ctx: Any, cw: Any) -> None:
    """StartOTelEnrichment requires the account to have resource-tags-on-telemetry enabled
    first (observabilityadmin:StartTelemetryEnrichment). Enable it on demand if needed."""
    try:
        cw.start_otel_enrichment()
        return
    except ClientError:
        pass

    try:
        oa = ctx.client("observabilityadmin")
    except Exception as exc:  # pragma: no cover - defensive, unknown service name variants
        raise AssertionError(f"observabilityadmin client unavailable: {exc}") from exc

    if not hasattr(oa, "start_telemetry_enrichment"):
        raise AssertionError("observabilityadmin.start_telemetry_enrichment not available in this botocore version")

    # StartTelemetryEnrichment is idempotent: a repeat call on an account that already has
    # it enabled succeeds, so any refusal here is a real failure.
    try:
        oa.start_telemetry_enrichment()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            f"could not enable telemetry-enrichment prerequisite: {err.get('Code')}: {err.get('Message')!r}"
        ) from exc

    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cw.start_otel_enrichment()
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"StartOTelEnrichment kept failing after enabling its prerequisite: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
