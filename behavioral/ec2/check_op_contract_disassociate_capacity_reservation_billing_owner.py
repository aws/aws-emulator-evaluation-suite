"""op-contract-disassociate-capacity-reservation-billing-owner."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disassociate-capacity-reservation-billing-owner"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateCapacityReservationBillingOwner with DryRun on an owned Capacity Reservation answers
    DryRunOperation, and an unknown reservation ID fails with InvalidCapacityReservationId.NotFound,
    each with its exact message."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    cr_id = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-capres-")}],
            }
        ],
    )["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)))

    consumer_account_id = "111122223333"

    # Boundary A: DryRun on a real, owned reservation with nothing pending short-circuits.
    code, message = _client_error(
        lambda: ec2.disassociate_capacity_reservation_billing_owner(
            CapacityReservationId=cr_id, UnusedReservationBillingOwnerId=consumer_account_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )

    # Boundary B: a sibling id (real shape, guaranteed nonexistent) is rejected distinctly
    # from the DryRun boundary.
    fake_id = _flip_last_hex_char(cr_id)
    code2, message2 = _client_error(
        lambda: ec2.disassociate_capacity_reservation_billing_owner(
            CapacityReservationId=fake_id, UnusedReservationBillingOwnerId=consumer_account_id
        )
    )
    assert code2 == "InvalidCapacityReservationId.NotFound", f"unexpected code: {code2!r}"
    assert message2 == f"Capacity Reservation ID '{fake_id}' could not be found", (
        f"unexpected InvalidCapacityReservationId.NotFound message: {message2!r}"
    )
    assert code2 != "DryRunOperation", "the not-found boundary must be distinct from the DryRun boundary"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _flip_last_hex_char(resource_id: str) -> str:
    """Flip the last hex character of a real resource ID, giving an ID of the same length and
    character set that is guaranteed to differ."""
    last = resource_id[-1]
    alphabet = "0123456789abcdef"
    flipped = alphabet[(alphabet.index(last) + 1) % len(alphabet)]
    return resource_id[:-1] + flipped


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
