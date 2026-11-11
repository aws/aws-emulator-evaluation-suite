"""op-contract-purchase-capacity-block-extension-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-purchase-capacity-block-extension-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseCapacityBlockExtension with a well-formed but unowned CapacityReservationId fails with
    InvalidCapacityReservationId.NotFound, resolved before the extension offering id, while the free
    DescribeCapacityBlockOfferings read succeeds as the positive control."""
    ec2 = ctx.client("ec2")

    # positive control: free, resource-less read on the same Capacity Block surface.
    ec2.describe_capacity_block_offerings(
        InstanceType="p4d.24xlarge", InstanceCount=1, CapacityDurationHours=24
    )

    err, message, _ = _client_error(
        lambda: ec2.purchase_capacity_block_extension(
            CapacityBlockExtensionOfferingId="not-a-real-offering-id",
            CapacityReservationId="cr-00000000000000000",
        )
    )
    assert err == "InvalidCapacityReservationId.NotFound", (
        f"expected InvalidCapacityReservationId.NotFound, got {err}"
    )
    assert message == "The capacity-reservation ID 'cr-00000000000000000' does not exist", f"unexpected InvalidCapacityReservationId.NotFound message: {message!r}"


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
