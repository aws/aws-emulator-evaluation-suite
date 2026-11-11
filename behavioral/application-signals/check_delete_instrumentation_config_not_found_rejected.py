"""delete-instrumentation-config-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-instrumentation-config-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an already-deleted instrumentation configuration is rejected with
    ResourceNotFoundException and Get still reports it absent, while creating and deleting a fresh
    configuration succeeds and is confirmed gone."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")
    file_path = "src/checkout/RefundService.py"

    created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="issueRefund"),
        CaptureConfiguration=_capture_configuration(),
    )
    location_hash = created["LocationHash"]

    first_delete = sig.delete_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        LocationIdentifier={"LocationHash": location_hash},
    )
    assert first_delete["DeletionStatus"] == "DELETED"

    code, message = _client_error(
        lambda: sig.delete_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": location_hash},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The requested instrumentation configuration does not exist.", (
        f"expected the second-delete not-found message, got {message!r}"
    )

    still_absent_code, still_absent_message = _client_error(
        lambda: sig.get_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": location_hash},
        )
    )
    assert still_absent_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {still_absent_code!r}"
    )
    assert still_absent_message == "The requested instrumentation configuration has been deleted.", (
        f"expected the deleted-config read message, got {still_absent_message!r}"
    )

    control_created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="issueRefundV2"),
        CaptureConfiguration=_capture_configuration(),
    )
    control_hash = control_created["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, control_hash)
    )
    control_delete = sig.delete_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        LocationIdentifier={"LocationHash": control_hash},
    )
    assert control_delete["DeletionStatus"] == "DELETED"

    control_absent_code, control_absent_message = _client_error(
        lambda: sig.get_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": control_hash},
        )
    )
    assert control_absent_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {control_absent_code!r}"
    )
    assert control_absent_message == "The requested instrumentation configuration has been deleted.", (
        f"expected the deleted-config read message, got {control_absent_message!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return the (code, message) it is rejected with; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
