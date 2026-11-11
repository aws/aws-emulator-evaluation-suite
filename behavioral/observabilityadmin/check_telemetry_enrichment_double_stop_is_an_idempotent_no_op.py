"""telemetry-enrichment-double-stop-is-an-idempotent-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-enrichment-double-stop-is-an-idempotent-no-op"
GROUP = "state"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:config-service-linked-recorder", "resource:account-singleton:observabilityadmin-telemetry-enrichment")
def run(ctx) -> None:
    """StartTelemetryEnrichment/StopTelemetryEnrichment move the feature between Stopped and
    Running (positive control), and a second StopTelemetryEnrichment on an already-Stopped feature
    succeeds as an idempotent no-op that leaves it Stopped, not a ConflictException."""
    client = ctx.client("observabilityadmin")

    # The feature is an account setting: snapshot it and put it back after the check.
    original = _get_status_or_stopped(client)
    ctx.on_cleanup(lambda: _restore_status(client, original))

    # Normalize to Stopped first.
    _stop_enrichment(client)
    _wait_for_status(client, {"Stopped"}, timeout_s=60)

    # StartTelemetryEnrichment can transiently conflict for a few seconds after the account's
    # status has already settled to Stopped -- GetStatus reflects the terminal state before the
    # backend has fully released it for the opposite transition. Retry the mutating call itself
    # on that specific conflict; this is genuine asynchrony, not a change to what is asserted.
    _call_with_conflict_retry(lambda: client.start_telemetry_enrichment(), timeout_s=45)
    ctx.on_cleanup(lambda: _stop_enrichment(client))
    away_status = _wait_for_status_not(client, "Stopped", timeout_s=90)
    assert away_status in ("Running", "Impaired"), (
        f"expected Running or Impaired after StartTelemetryEnrichment, got {away_status!r}"
    )

    _call_with_conflict_retry(lambda: client.stop_telemetry_enrichment(), timeout_s=45)
    stopped_status = _wait_for_status(client, {"Stopped"}, timeout_s=90)
    assert stopped_status == "Stopped", f"expected Stopped after StopTelemetryEnrichment, got {stopped_status!r}"

    # idempotent no-op: stopping an already-Stopped feature succeeds silently, it is not a conflict
    client.stop_telemetry_enrichment()

    still_stopped = _get_status_or_stopped(client)
    assert still_stopped == "Stopped", f"expected status to remain Stopped after the redundant call, got {still_stopped!r}"


# ===== helpers =====
def _get_status_or_stopped(client) -> str:
    # Before the resource-tags-for-telemetry feature has ever been started, GetStatus
    # raises ResourceNotFoundException rather than reporting Status=Stopped -- treat that
    # as the Stopped state for polling purposes (it is the same "not running" condition).
    try:
        return client.get_telemetry_enrichment_status().get("Status")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return "Stopped"
        raise


def _stop_enrichment(client) -> None:
    """StopTelemetryEnrichment, retrying a transient ConflictException; a feature that was never
    started (ResourceNotFoundException) has nothing to stop; any other error raises."""
    try:
        _call_with_conflict_retry(lambda: client.stop_telemetry_enrichment(), timeout_s=45)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _call_with_conflict_retry(fn, timeout_s: float, interval_s: float = 4.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _restore_status(client, original: str) -> None:
    """Put the account's telemetry enrichment back to Running if it was running before."""
    if original not in ("Running", "Impaired"):
        return
    _wait_for_status(client, {"Stopped"}, timeout_s=90)
    _call_with_conflict_retry(lambda: client.start_telemetry_enrichment(), timeout_s=45)
    _wait_for_status_not(client, "Stopped", timeout_s=90)


def _wait_for_status(client, expected: set, timeout_s: float, interval_s: float = 4.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _get_status_or_stopped(client)
        if status in expected:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {expected} (last={status})")


def _wait_for_status_not(client, unexpected: str, timeout_s: float, interval_s: float = 4.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _get_status_or_stopped(client)
        if status != unexpected:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"status never left {unexpected!r} (last={status})")



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
