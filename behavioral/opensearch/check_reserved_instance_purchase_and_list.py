"""reserved-instance-purchase-and-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-instance-purchase-and-list"
GROUP = 'reserved-instances'
SERVICES = ['opensearch']


def _error(fn) -> tuple:
    """Call fn() and return its botocore error (code, message); an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedInstanceOffering without InstanceCount fails ValidationException on
    instanceCount, DescribeReservedInstances lists ReservedInstances, and an unknown
    ReservedInstanceId raises ResourceNotFoundException."""
    osc = ctx.client("opensearch")

    listed = osc.describe_reserved_instances()
    assert "ReservedInstances" in listed, f"expected a ReservedInstances key, got keys {sorted(listed)}"

    # InstanceCount is omitted so validation refuses before the offering id is resolved; no
    # purchase is ever made, as a reservation is a non-cancellable billing commitment.
    bogus_offering_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: osc.purchase_reserved_instance_offering(
            ReservedInstanceOfferingId=bogus_offering_id,
            ReservationName=ctx.unique_name("ri"),
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException, got {code}"
    )
    assert message == (
        "1 validation error detected: Value '0' at 'instanceCount' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), f"unexpected validation message: {message!r}"

    bogus_reserved_id = "00000000-0000-0000-0000-000000000000"
    code2, message2 = _error(
        lambda: osc.describe_reserved_instances(ReservedInstanceId=bogus_reserved_id)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert message2 == "Reservation id not found", f"unexpected not-found message: {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
