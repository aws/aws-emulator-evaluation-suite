"""describe-fhir-datastore-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-fhir-datastore-not-found"
GROUP = "error-semantics"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeFHIRDatastore on a well-formed id that was never created raises
    ResourceNotFoundException; the identical call against a real id succeeds."""
    healthlake = ctx.client("healthlake")

    name = ctx.unique_name("sim2real-hl-notfound-")
    created = healthlake.create_fhir_datastore(
        DatastoreName=name,
        DatastoreTypeVersion="R4",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    real_id = created["DatastoreId"]
    ctx.on_cleanup(lambda: _swallow(lambda: healthlake.delete_fhir_datastore(DatastoreId=real_id)))

    # positive control: describe on the real, just-created id succeeds.
    described = healthlake.describe_fhir_datastore(DatastoreId=real_id)
    assert described["DatastoreProperties"]["DatastoreId"] == real_id, (
        f"expected DescribeFHIRDatastore to return {real_id!r}, "
        f"got {described['DatastoreProperties']['DatastoreId']!r}"
    )

    bogus_id = _flip_last_char(real_id)
    code, message = _error_code_and_message(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=bogus_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = "Could not find specified datastore."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _flip_last_char(real_id: str) -> str:
    """A well-formed id derived from a real one by perturbing exactly one character,
    so it stays within DatastoreId's length/pattern constraints but was never created."""
    last = real_id[-1]
    replacement = "0" if last != "0" else "1"
    return real_id[:-1] + replacement


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
