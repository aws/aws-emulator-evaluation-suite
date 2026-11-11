"""update-datastore-while-creating-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-datastore-while-creating-rejected"
GROUP = "overly-permissive"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFHIRDatastore on a datastore still in CREATING is rejected with AccessDeniedException ("Specified datastore is not active."); the name only changes once ACTIVE."""
    healthlake = ctx.client("healthlake")
    original_name = ctx.unique_name("sim2real-hl-conflict-")

    created = healthlake.create_fhir_datastore(
        DatastoreName=original_name,
        DatastoreTypeVersion="R4",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    datastore_id = created["DatastoreId"]
    assert created["DatastoreStatus"] == "CREATING", f"expected CREATING, got {created['DatastoreStatus']!r}"

    def _cleanup():
        try:
            healthlake.delete_fhir_datastore(DatastoreId=datastore_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # precondition: the check holds the in-progress window itself -- the datastore it just
    # created is still being provisioned when the update is sent.
    before = healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]
    assert before["DatastoreStatus"] == "CREATING", (
        f"precondition: expected the new datastore to still be CREATING, got {before['DatastoreStatus']!r}"
    )

    attempted_name = ctx.unique_name("sim2real-hl-shouldnotstick-")
    code, detail = _error_code_and_message(
        lambda: healthlake.update_fhir_datastore(DatastoreId=datastore_id, DatastoreName=attempted_name)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r} detail={detail!r}"
    expected = "Specified datastore is not active."
    assert detail == expected, f"expected message {expected!r}, got {detail!r}"

    # effect absence: the rejected update never changed the name.
    still_original = healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]
    assert still_original["DatastoreName"] == original_name, (
        f"expected name unchanged at {original_name!r}, got {still_original['DatastoreName']!r}"
    )

    active = _poll_until(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"],
        lambda p: p["DatastoreStatus"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2100.0,
        interval_s=20.0,
    )
    assert active["DatastoreStatus"] == "ACTIVE", f"datastore reached {active['DatastoreStatus']}"

    # positive control: the identical update succeeds once the datastore is ACTIVE.
    new_name = ctx.unique_name("sim2real-hl-renamed-")
    healthlake.update_fhir_datastore(DatastoreId=datastore_id, DatastoreName=new_name)
    updated = healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]
    assert updated["DatastoreName"] == new_name, (
        f"expected renamed to {new_name!r}, got {updated['DatastoreName']!r}"
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
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
