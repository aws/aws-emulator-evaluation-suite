"""op-contract-describe-capacity-reservation-topology."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-capacity-reservation-topology"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityReservationTopology: list-shape success and the documented
    invalid-pagination-token rejection (a garbage NextToken is rejected, the standard
    EC2 pagination contract shared by essentially all Describe* list operations)."""
    ec2 = ctx.client("ec2")

    # Success path: no args always succeeds with the topology list shape.
    resp = ec2.describe_capacity_reservation_topology()
    assert "CapacityReservations" in resp, f"expected CapacityReservations in response, got {resp!r}"
    assert isinstance(resp["CapacityReservations"], list), (
        f"expected CapacityReservations to be a list, got {resp['CapacityReservations']!r}"
    )

    # Error boundary (distinct axis: invalid pagination token, not a bogus-id
    # NotFound): supplying a garbage NextToken is rejected. Note: combining
    # CapacityReservationIds with MaxResults is NOT rejected by this API (ids and
    # pagination are independent, orthogonal parameters), so that combination is not
    # a valid rejection boundary.
    # This operation, like several other Describe* APIs, mints a dedicated
    # InvalidPaginationToken sentinel for a garbage NextToken rather than a generic
    # InvalidParameterValue.
    token_code, token_code_msg = _error(
        lambda: ec2.describe_capacity_reservation_topology(NextToken="sim2real-bogus-token")
    )
    assert token_code == "InvalidPaginationToken", (
        f"expected InvalidPaginationToken, got {token_code}"
    )
    assert token_code_msg == "The passed pagination token is invalid", (
        f"expected the exact InvalidPaginationToken message, got {token_code_msg!r}"
    )

    # Secondary boundary for depth: DryRun still short-circuits normally.
    dry_code, dry_code_msg = _error(lambda: ec2.describe_capacity_reservation_topology(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
