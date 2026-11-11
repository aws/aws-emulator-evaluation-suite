"""create-datastore-invalid-type-version-validation-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-datastore-invalid-type-version-validation-error"
GROUP = "error-semantics"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFHIRDatastore rejects a DatastoreTypeVersion outside the FHIRVersion enum (only R4
    exists) with ValidationException; the identical call with R4 succeeds, and no datastore is
    ever created under the rejected name."""
    healthlake = ctx.client("healthlake")

    # positive control: a valid DatastoreTypeVersion succeeds.
    good_name = ctx.unique_name("sim2real-hl-goodversion-")
    created = healthlake.create_fhir_datastore(
        DatastoreName=good_name, DatastoreTypeVersion="R4", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    datastore_id = created["DatastoreId"]
    assert created["DatastoreStatus"] == "CREATING", f"expected CREATING, got {created['DatastoreStatus']!r}"
    ctx.on_cleanup(lambda: _best_effort(lambda: healthlake.delete_fhir_datastore(DatastoreId=datastore_id)))

    bad_name = ctx.unique_name("sim2real-hl-badversion-")
    code, message = _error_code_and_message(
        lambda: healthlake.create_fhir_datastore(DatastoreName=bad_name, DatastoreTypeVersion="R5")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'datastoreTypeVersion' failed to satisfy constraint: "
        "Member must satisfy enum value set: [R4]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absence: the rejected call never created a datastore under that name.
    listed = healthlake.list_fhir_datastores(Filter={"DatastoreName": bad_name})["DatastorePropertiesList"]
    assert listed == [], f"expected no datastores named {bad_name!r}, got {listed!r}"


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code_and_message(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
