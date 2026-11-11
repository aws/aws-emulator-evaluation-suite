"""instrumentation-status-error-cause-via-report."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instrumentation-status-error-cause-via-report"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reporting an ERROR status with a specific ErrorCause via ReportInstrumentationConfigurationStatus
    makes it visible under GetInstrumentationConfigurationStatus's ERROR status filter, with the
    ErrorCause preserved on the event (Status is a query filter, not a mutable current-state field)."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")
    file_path = "src/checkout/InventoryService.py"

    created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="reserveStock"),
        CaptureConfiguration=_capture_configuration(),
    )
    location_hash = created["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, location_hash)
    )

    sig.report_instrumentation_configuration_status(
        Service=service,
        Environment=environment,
        Configurations=[
            {
                "InstrumentationType": "PROBE",
                "SignalType": "SNAPSHOT",
                "LocationHash": location_hash,
                "Status": "ERROR",
                "Time": _report_time(),
                "ErrorCause": "METHOD_NOT_FOUND",
            }
        ],
    )

    error_events = _poll_until(
        lambda: sig.get_instrumentation_configuration_status(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": location_hash},
            Status="ERROR",
        )["Events"],
        lambda events: len(events) > 0,
        timeout_s=30,
    )
    assert len(error_events) >= 1
    assert any(e.get("ErrorCause") == "METHOD_NOT_FOUND" for e in error_events)


def _report_time() -> dt.datetime:
    """The start of the current minute: status events are kept at minute resolution, and a time at
    the minute's start never lands after now, so the default query window already holds it."""
    return dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)


def _delete_instrumentation_ignore_missing(sig, service, environment, location_hash) -> None:
    try:
        sig.delete_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": location_hash},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _code_location(file_path: str, method_name: str | None = None) -> dict:
    loc = {"Language": "Python", "FilePath": file_path, "CodeUnit": "sim2real_module"}
    if method_name:
        loc["MethodName"] = method_name
    return {"CodeLocation": loc}


def _capture_configuration(max_hits: int = 50) -> dict:
    return {"CodeCapture": {"CaptureLimits": {"MaxHits": max_hits}}}


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
