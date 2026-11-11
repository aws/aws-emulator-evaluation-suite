"""op-contract-acceptCapacityReservationBillingOwnership-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptCapacityReservationBillingOwnership-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptCapacityReservationBillingOwnership with DryRun on a created Capacity Reservation fails
    DryRunOperation with its exact message, and on an id EC2 never issues fails
    InvalidCapacityReservationId.Malformed with its exact message; both carry a RequestId.
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
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-")}],
            }
        ],
    )["CapacityReservation"]
    cr_id = cr["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_capacity_reservation(ec2, cr_id))

    info = _client_error_info(
        lambda: ec2.accept_capacity_reservation_billing_ownership(
            CapacityReservationId=cr_id, DryRun=True
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    # AcceptCapacityReservationBillingOwnership answers an id EC2 could never have issued with
    # InvalidCapacityReservationId.Malformed, not NotFound: the real id with a non-zero leading hex
    # digit keeps the shape but leaves the range.
    fake_id = f"cr-{'e' if cr_id[3] == 'f' else 'f'}{cr_id[4:]}"
    info2 = _client_error_info(
        lambda: ec2.accept_capacity_reservation_billing_ownership(CapacityReservationId=fake_id)
    )
    assert info2["code"] == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {info2['code']!r}"
    )
    assert info2["message"] == f"Capacity Reservation ID '{fake_id}' is malformed", (
        f"unexpected InvalidCapacityReservationId.Malformed message {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """The code, message and request id of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _cancel_capacity_reservation(ec2, cr_id: str) -> None:
    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
