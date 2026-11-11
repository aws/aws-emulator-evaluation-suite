"""fhir-datastore-full-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fhir-datastore-full-lifecycle-transitions"
GROUP = "state"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DatastoreStatus transitions CREATING->ACTIVE on create, then ACTIVE->DELETING->DELETED on delete."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-hl-ds-")

    created = healthlake.create_fhir_datastore(
        DatastoreName=name,
        DatastoreTypeVersion="R4",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )
    datastore_id = created["DatastoreId"]
    assert created["DatastoreStatus"] == "CREATING", (
        f"expected CREATING on create response, got {created['DatastoreStatus']!r}"
    )

    def _cleanup():
        try:
            healthlake.delete_fhir_datastore(DatastoreId=datastore_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    active = _poll_until(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=datastore_id)[
            "DatastoreProperties"
        ]["DatastoreStatus"],
        lambda status: status in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2100.0,
        interval_s=20.0,
    )
    assert active == "ACTIVE", f"datastore reached {active} instead of ACTIVE"

    deleted_resp = healthlake.delete_fhir_datastore(DatastoreId=datastore_id)
    assert deleted_resp["DatastoreStatus"] == "DELETING", (
        f"expected DELETING on delete response, got {deleted_resp['DatastoreStatus']!r}"
    )

    final_status = _poll_until(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=datastore_id)[
            "DatastoreProperties"
        ]["DatastoreStatus"],
        lambda status: status == "DELETED",
        timeout_s=2100.0,
        interval_s=20.0,
    )
    assert final_status == "DELETED", f"expected DELETED, last observed {final_status!r}"

    # The dead id is unusable — a mutation against it fails once it is gone.
    rename_code, rename_message = _error_code_and_message(
        lambda: healthlake.update_fhir_datastore(
            DatastoreId=datastore_id, DatastoreName=ctx.unique_name("sim2real-hl-dead-")
        )
    )
    # Measured against real AWS, not guessed: real AWS refuses a mutation on a DELETED datastore
    # with AccessDeniedException ("not active") rather than ResourceNotFoundException or
    # ConflictException.
    assert rename_code == "AccessDeniedException", (
        f"expected update on a DELETED datastore to fail with AccessDeniedException, got {rename_code!r}"
    )
    expected_message = "Specified datastore is not active."
    assert rename_message == expected_message, (
        f"expected message {expected_message!r}, got {rename_message!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
