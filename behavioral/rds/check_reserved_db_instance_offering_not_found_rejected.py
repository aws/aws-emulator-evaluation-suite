"""reserved-db-instance-offering-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-db-instance-offering-not-found-rejected"
GROUP = "reserved_instances"
SERVICES = ["rds"]

ERR_OFFERING_NOT_FOUND = "ReservedDBInstancesOfferingNotFound"
ERR_RESERVED_INSTANCE_NOT_FOUND = "ReservedDBInstanceNotFound"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedDBInstancesOffering and DescribeReservedDBInstancesOfferings reject a
    never-issued offering id, and DescribeReservedDBInstances rejects a never-purchased
    reservation id; a real, published offering id still describes."""
    rds = ctx.client("rds")
    # ReservedDBInstancesOfferingId is UUID-shaped; derive one deterministically from a unique
    # name so the id is well-formed but was never issued by AWS.
    bogus_offering_id = str(uuid.uuid5(uuid.NAMESPACE_OID, ctx.unique_name("sim2real-behav-offering-")))

    code, message = _error_code(
        lambda: rds.describe_reserved_db_instances_offerings(
            ReservedDBInstancesOfferingId=bogus_offering_id
        )
    )
    assert code == ERR_OFFERING_NOT_FOUND, f"unexpected error code: {code!r}"
    expected = f"ReservedDBInstanceOffering {bogus_offering_id} not found."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    purchase_code, purchase_message = _error_code(
        lambda: rds.purchase_reserved_db_instances_offering(
            ReservedDBInstancesOfferingId=bogus_offering_id
        )
    )
    assert purchase_code == ERR_OFFERING_NOT_FOUND, f"unexpected error code: {purchase_code!r}"
    assert purchase_message == expected, (
        f"unexpected message: {purchase_message!r} (expected {expected!r})"
    )

    bogus_reservation_id = ctx.unique_name("sim2real-behav-reservedid-")
    reserved_code, reserved_message = _error_code(
        lambda: rds.describe_reserved_db_instances(ReservedDBInstanceId=bogus_reservation_id)
    )
    assert reserved_code == ERR_RESERVED_INSTANCE_NOT_FOUND, (
        f"unexpected error code: {reserved_code!r}"
    )
    expected_reserved = f"ReservedDBInstance {bogus_reservation_id} not found."
    assert reserved_message == expected_reserved, (
        f"unexpected message: {reserved_message!r} (expected {expected_reserved!r})"
    )

    # Positive control: an unfiltered describe succeeds and lists real, published offerings.
    offerings = rds.describe_reserved_db_instances_offerings()["ReservedDBInstancesOfferings"]
    assert offerings, "expected at least one published reserved DB instance offering"
    real_offering_id = offerings[0]["ReservedDBInstancesOfferingId"]
    described = rds.describe_reserved_db_instances_offerings(
        ReservedDBInstancesOfferingId=real_offering_id
    )["ReservedDBInstancesOfferings"]
    assert len(described) == 1 and described[0]["ReservedDBInstancesOfferingId"] == real_offering_id, (
        f"expected the real offering id to describe on its own, got {described!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
