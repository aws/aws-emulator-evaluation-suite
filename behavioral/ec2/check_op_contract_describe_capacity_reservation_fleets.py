"""op-contract-describe-capacity-reservation-fleets."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-capacity-reservation-fleets"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityReservationFleets: list-shape success, DryRun permission-check
    contract, and the InvalidCapacityReservationFleetId.Malformed rejection boundary for
    a fleet ID AWS never minted."""
    ec2 = ctx.client("ec2")

    # Success path: calling with no filters always succeeds and returns a list shape.
    resp = ec2.describe_capacity_reservation_fleets()
    assert "CapacityReservationFleets" in resp
    assert isinstance(resp["CapacityReservationFleets"], list)

    # Error boundary #1: DryRun short-circuits with the documented sentinel error.
    dry_error = _client_error(lambda: ec2.describe_capacity_reservation_fleets(DryRun=True))
    assert dry_error["Code"] == "DryRunOperation", f"expected DryRunOperation, got {dry_error}"
    assert dry_error.get("Message") == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_error!r}"
    )

    # Error boundary #2 (distinct contract): an ID passed through CapacityReservationFleetIds is
    # validated up front and rejected, not silently filtered to an empty result. Capacity
    # Reservation Fleet IDs carry AWS-side validity information beyond "prefix + hex of the right
    # length": real AWS rejects any ID it did not itself mint -- including a
    # synthetic all-zero-body id -- as InvalidCapacityReservationFleetId.Malformed, with a message
    # naming the id.
    fake_fleet_id = "crf-" + "0" * 17
    rejected = _client_error(
        lambda: ec2.describe_capacity_reservation_fleets(
            CapacityReservationFleetIds=[fake_fleet_id]
        )
    )
    assert rejected["Code"] == "InvalidCapacityReservationFleetId.Malformed", (
        f"expected InvalidCapacityReservationFleetId.Malformed, got {rejected}"
    )
    assert rejected.get("Message") == f"Capacity Reservation Fleet ID '{fake_fleet_id}' is malformed", (
        f"expected the exact InvalidCapacityReservationFleetId.Malformed message, got {rejected!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
