"""op-contract-associate-capacity-reservation-billing-owner."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-associate-capacity-reservation-billing-owner"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateCapacityReservationBillingOwner: DryRun confirms the request would be accepted
    for a real reservation; a nonexistent CapacityReservationId is rejected."""
    ec2 = ctx.client("ec2")
    reservation_id = _create_short_lived_reservation(ctx)

    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.associate_capacity_reservation_billing_owner(
            CapacityReservationId=reservation_id,
            UnusedReservationBillingOwnerId="111122223333",
            DryRun=True,
        )
    )
    assert dry_run_code == "DryRunOperation", f"unexpected dry-run code: {dry_run_code}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected dry-run message: {dry_run_message!r}"
    )

    malformed_id = "cr-00000000000000000"
    code, message = _client_error(
        lambda: ec2.associate_capacity_reservation_billing_owner(
            CapacityReservationId=malformed_id,
            UnusedReservationBillingOwnerId="111122223333",
        )
    )
    assert code == "InvalidCapacityReservationId.Malformed", f"unexpected error code: {code}"
    expected = f"Capacity Reservation ID '{malformed_id}' is malformed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message); an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_short_lived_reservation(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az = azs[0]["ZoneName"]
    resp = ec2.create_capacity_reservation(
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
    )
    reservation_id = resp["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=reservation_id))
    return reservation_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
