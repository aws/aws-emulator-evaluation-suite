"""instrumentation-status-transition-ready-to-active-via-report."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instrumentation-status-transition-ready-to-active-via-report"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fresh instrumentation config has no status history until an agent reports it; reporting
    READY then ACTIVE via ReportInstrumentationConfigurationStatus makes each independently visible
    through GetInstrumentationConfigurationStatus's per-status Events filter."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")
    file_path = "src/checkout/OrderService.py"

    created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="placeOrder"),
        CaptureConfiguration=_capture_configuration(),
    )
    location_hash = created["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, location_hash)
    )

    # A fresh config has no status history at all -- confirm the docstring's premise before
    # relying on it, and establish that the filter starts at zero rather than "everything ever
    # reported regardless of Status".
    fresh_ready = _get_events(sig, service, environment, location_hash, "READY")
    assert fresh_ready == [], f"expected no READY events before any report, got {fresh_ready!r}"
    fresh_active = _get_events(sig, service, environment, location_hash, "ACTIVE")
    assert fresh_active == [], f"expected no ACTIVE events before any report, got {fresh_active!r}"

    # GetInstrumentationConfigurationStatus is queried BY status (it is a filter, not a
    # mutable "current status" field) -- Status in the response just echoes the query,
    # and each Event only carries Time (+ optional ErrorCause). Report READY explicitly
    # and confirm it shows up under that filter.
    _report_status(sig, service, environment, location_hash, "READY")

    ready_events = _poll_until(
        lambda: _get_events(sig, service, environment, location_hash, "READY"),
        lambda events: len(events) > 0,
        timeout_s=30,
    )
    assert len(ready_events) >= 1, f"expected >=1 READY event after report, got {ready_events!r}"

    # The filter must discriminate, not just accumulate: ACTIVE has never been reported, so
    # querying Status=ACTIVE now must stay empty even though READY events exist for this
    # location -- a target that ignores the Status filter and returns full history would fail
    # this and pass everything else in the file.
    still_no_active = _get_events(sig, service, environment, location_hash, "ACTIVE")
    assert still_no_active == [], (
        f"expected no ACTIVE events before ACTIVE was ever reported, got {still_no_active!r}"
    )

    _report_status(sig, service, environment, location_hash, "ACTIVE")

    active_events = _poll_until(
        lambda: _get_events(sig, service, environment, location_hash, "ACTIVE"),
        lambda events: len(events) > 0,
        timeout_s=30,
    )
    assert len(active_events) >= 1, f"expected >=1 ACTIVE event after report, got {active_events!r}"

    # The earlier READY event is still queryable independently -- reporting ACTIVE does not
    # erase prior status history under a different status filter.
    still_ready = _get_events(sig, service, environment, location_hash, "READY")
    assert len(still_ready) >= 1, f"expected READY history to survive ACTIVE report, got {still_ready!r}"


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
