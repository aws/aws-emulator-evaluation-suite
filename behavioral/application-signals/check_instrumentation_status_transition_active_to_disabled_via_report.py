"""instrumentation-status-transition-active-to-disabled-via-report."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instrumentation-status-transition-active-to-disabled-via-report"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reporting ACTIVE then DISABLED via ReportInstrumentationConfigurationStatus makes each
    queryable through GetInstrumentationConfigurationStatus's per-status Events filter: each
    report adds event history rather than overwriting a current state."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")
    file_path = "src/checkout/ShippingService.py"

    created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="calculateShipping"),
        CaptureConfiguration=_capture_configuration(),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    location_hash = created["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, location_hash)
    )

    _report_status(sig, service, environment, location_hash, "ACTIVE")
    active_events = _poll_until(
        lambda: _get_events(sig, service, environment, location_hash, "ACTIVE"),
        lambda events: len(events) > 0,
        timeout_s=30,
    )
    assert len(active_events) >= 1, f"expected >=1 ACTIVE event after report, got {active_events!r}"

    _report_status(sig, service, environment, location_hash, "DISABLED")
    disabled_events = _poll_until(
        lambda: _get_events(sig, service, environment, location_hash, "DISABLED"),
        lambda events: len(events) > 0,
        timeout_s=30,
    )
    assert len(disabled_events) >= 1, (
        f"expected >=1 DISABLED event after report, got {disabled_events!r}"
    )

    # The ACTIVE history remains queryable after DISABLED is reported -- distinct status
    # filters are independent event streams, not a single overwritten field.
    still_active = _get_events(sig, service, environment, location_hash, "ACTIVE")
    assert len(still_active) >= 1, (
        f"expected ACTIVE events to remain queryable after DISABLED was reported, got {still_active!r}"
    )


def _get_events(sig, service, environment, location_hash, status) -> list:
    return sig.get_instrumentation_configuration_status(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        LocationIdentifier={"LocationHash": location_hash},
        Status=status,
    )["Events"]


def _report_status(sig, service, environment, location_hash, status) -> None:
    sig.report_instrumentation_configuration_status(
        Service=service,
        Environment=environment,
        Configurations=[
            {
                "InstrumentationType": "PROBE",
                "SignalType": "SNAPSHOT",
                "LocationHash": location_hash,
                "Status": status,
                "Time": _report_time(),
            }
        ],
    )


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

