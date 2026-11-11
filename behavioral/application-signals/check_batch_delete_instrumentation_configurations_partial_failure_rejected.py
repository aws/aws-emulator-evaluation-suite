"""batch-delete-instrumentation-configurations-partial-failure-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-instrumentation-configurations-partial-failure-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteInstrumentationConfigurations with one real and one nonexistent ARN deletes only
    the real one: DeletedCount is 1, the missing ARN is a per-item ResourceNotFoundException in
    Errors, the real config is gone and a config left out of the batch is untouched."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")

    to_delete = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location("src/checkout/TaxService.py", method_name="calculateTax"),
        CaptureConfiguration=_capture_configuration(),
    )
    to_delete_hash = to_delete["LocationHash"]
    to_delete_arn = to_delete["ARN"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, to_delete_hash)
    )

    sibling = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location("src/checkout/TaxService.py", method_name="calculateTaxV2"),
        CaptureConfiguration=_capture_configuration(),
    )
    sibling_hash = sibling["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, sibling_hash)
    )

    bogus_arn = to_delete_arn[:-16] + "0000000000000000"

    resp = sig.batch_delete_instrumentation_configurations(
        DeletionTarget={
            "ResourceArns": {
                "ResourceArns": [to_delete_arn, bogus_arn],
                "InstrumentationType": "PROBE",
            }
        }
    )

    assert resp["DeletedCount"] == 1, f"expected DeletedCount=1, got {resp['DeletedCount']!r}"
    successful_arns = {s.get("ResourceArn") for s in resp["SuccessfulDeletions"]}
    assert to_delete_arn in successful_arns, (
        f"expected {to_delete_arn!r} in SuccessfulDeletions, got {successful_arns!r}"
    )
    error_entries = {e["ResourceArn"]: (e["Code"], e.get("Message")) for e in resp["Errors"]}
    assert error_entries.get(bogus_arn) == (
        "ResourceNotFoundException",
        "The instrumentation config is already deleted or expired.",
    ), f"expected Errors[{bogus_arn!r}] to be a not-found entry, got {error_entries!r}"

    deleted_code, deleted_message = _client_error(
        lambda: sig.get_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": to_delete_hash},
        )
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected deleted config read to fail with ResourceNotFoundException, got {deleted_code!r}"
    )
    assert deleted_message == "The requested instrumentation configuration has been deleted.", (
        f"expected the deleted-config read message, got {deleted_message!r}"
    )

    sibling_still_there = sig.get_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        LocationIdentifier={"LocationHash": sibling_hash},
    )["Configuration"]
    assert sibling_still_there["LocationHash"] == sibling_hash, (
        f"expected untouched sibling {sibling_hash!r}, got {sibling_still_there.get('LocationHash')!r}"
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
