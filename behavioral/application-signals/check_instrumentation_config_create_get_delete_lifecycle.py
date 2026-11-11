"""instrumentation-config-create-get-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instrumentation-config-create-get-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created instrumentation configuration is retrievable by LocationHash, then gone after delete."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")
    file_path = "src/payment/PaymentProcessor.py"

    created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="processPayment"),
        CaptureConfiguration=_capture_configuration(),
    )
    location_hash = created["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, location_hash)
    )

    assert created["Service"] == service, f"expected Service={service!r}, got {created['Service']!r}"
    assert created["Environment"] == environment, (
        f"expected Environment={environment!r}, got {created['Environment']!r}"
    )
    assert created["Location"]["CodeLocation"]["FilePath"] == file_path, (
        f"expected FilePath={file_path!r}, got {created['Location']['CodeLocation']['FilePath']!r}"
    )

    got = sig.get_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        LocationIdentifier={"LocationHash": location_hash},
    )["Configuration"]
    assert got["Service"] == service, f"expected Service={service!r}, got {got['Service']!r}"
    assert got["Environment"] == environment, (
        f"expected Environment={environment!r}, got {got['Environment']!r}"
    )
    assert got["LocationHash"] == location_hash, (
        f"expected LocationHash={location_hash!r}, got {got['LocationHash']!r}"
    )
    assert got["Location"]["CodeLocation"]["MethodName"] == "processPayment", (
        f"expected MethodName='processPayment', got {got['Location']['CodeLocation']['MethodName']!r}"
    )

    delete_resp = sig.delete_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        LocationIdentifier={"LocationHash": location_hash},
    )
    assert delete_resp["DeletionStatus"] == "DELETED", (
        f"expected DeletionStatus='DELETED', got {delete_resp['DeletionStatus']!r}"
    )

    code, message = _client_error(
        lambda: sig.get_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": location_hash},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code!r}"
    )
    assert message == "The requested instrumentation configuration has been deleted.", (
        f"expected the deleted-config read message, got {message!r}"
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
