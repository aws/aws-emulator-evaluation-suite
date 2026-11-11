"""telemetry-evaluation-start-stop-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-evaluation-start-stop-lifecycle"
GROUP = "state"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:observabilityadmin-telemetry-evaluation")
def run(ctx) -> None:
    """StartTelemetryEvaluation drives the account-wide onboarding status from a non-running
    state to RUNNING, and StopTelemetryEvaluation drives it back to STOPPED, as observed through
    GetTelemetryEvaluationStatus."""
    client = ctx.client("observabilityadmin")

    # Normalize starting state: if evaluation is already running, stop it first. An account whose
    # earlier start failed (FAILED_START) is also not running, and Start retries from it.
    _stop_evaluation(client)
    _wait_for_status(client, {"STOPPED", "NOT_STARTED", "FAILED_START"}, timeout_s=90)

    _ensure_telemetry_enablement_slr(ctx)
    client.start_telemetry_evaluation()
    ctx.on_cleanup(lambda: _stop_evaluation(client))
    running_status = _wait_for_status(client, {"RUNNING"}, timeout_s=120)
    assert running_status == "RUNNING", f"expected RUNNING, got {running_status!r}"

    client.stop_telemetry_evaluation()
    stopped_status = _wait_for_status(client, {"STOPPED"}, timeout_s=120)
    assert stopped_status == "STOPPED", f"expected STOPPED, got {stopped_status!r}"


# ===== helpers =====
def _stop_evaluation(client) -> None:
    """StopTelemetryEvaluation when evaluation is RUNNING (or STARTING, once it is RUNNING); any
    other state has nothing to stop. A failed Stop raises."""
    status = client.get_telemetry_evaluation_status().get("Status")
    if status == "STARTING":
        status = _wait_for_status(client, {"RUNNING"}, timeout_s=120)
    if status == "RUNNING":
        client.stop_telemetry_evaluation()


def _ensure_telemetry_enablement_slr(ctx) -> None:
    # StartTelemetryEvaluation depends on the AWSServiceRoleForObservabilityAdmin_
    # TelemetryEnablement service-linked role. In some accounts the service fails to
    # auto-create it (surfaced as Status=FAILED_START, FailureReason=SLR_UNAVAILABLE) --
    # creating it explicitly up front works around that race.
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(
            AWSServiceName="telemetry-enablement.observabilityadmin.amazonaws.com"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


_FAILURE_STATUSES = frozenset({"FAILED_START", "FAILED_STOP"})


def _wait_for_status(client, expected: set, timeout_s: float, interval_s: float = 4.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    resp: dict = {}
    while time.monotonic() < deadline:
        resp = client.get_telemetry_evaluation_status()
        status = resp.get("Status")
        if status in expected:
            return status
        if status in _FAILURE_STATUSES:
            raise AssertionError(
                f"telemetry evaluation entered {status!r} while waiting for {expected}: "
                f"failure_reason={resp.get('FailureReason')!r} "
                f"region_statuses={resp.get('RegionStatuses')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {expected} (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
