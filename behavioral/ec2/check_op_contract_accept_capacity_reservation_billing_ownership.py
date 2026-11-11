"""op-contract-acceptCapacityReservationBillingOwnership."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptCapacityReservationBillingOwnership"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptCapacityReservationBillingOwnership with DryRun on a created Capacity Reservation fails
    DryRunOperation, and without DryRun on the same reservation after cancelling it fails
    InvalidState, each with its exact message.
    """
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    cr = ec2.create_capacity_reservation(
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
    )["CapacityReservation"]
    cr_id = cr["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_capacity_reservation(ec2, cr_id))

    info = _error_info(
        lambda: ec2.accept_capacity_reservation_billing_ownership(
            CapacityReservationId=cr_id, DryRun=True
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )

    ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)

    info2 = _error_info(
        lambda: ec2.accept_capacity_reservation_billing_ownership(CapacityReservationId=cr_id)
    )
    assert info2["code"] == "InvalidState", f"expected InvalidState, got {info2['code']!r}"
    expected2 = (
        "You can't assign billing of a Capacity Reservation that is in the cancelled state. "
        "Wait for the Capacity Reservation to reach the active state and then try again."
    )
    assert info2["message"] == expected2, (
        f"expected message {expected2!r}, got {info2['message']!r}"
    )


def _error_info(fn):
    """Call fn(); return its botocore error {code, message}. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _cancel_capacity_reservation(ec2, cr_id: str) -> None:
    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
