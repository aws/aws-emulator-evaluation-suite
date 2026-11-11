"""op-contract-purchase-capacity-block-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-purchase-capacity-block-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseCapacityBlock with a malformed offering ID is rejected with
    InvalidCapacityBlockOfferingIdMalformed; a real purchase commits non-refundable spend, so only the
    rejection is exercised."""
    ec2 = ctx.client("ec2")

    # DescribeCapacityBlockOfferings is free and part of the same contract surface.
    ec2.describe_capacity_block_offerings(
        InstanceType="p4d.24xlarge", InstanceCount=1, CapacityDurationHours=24
    )

    err, message, _ = _client_error(
        lambda: ec2.purchase_capacity_block(
            CapacityBlockOfferingId="not-a-real-offering-id", InstancePlatform="Linux/UNIX"
        )
    )
    assert err == "InvalidCapacityBlockOfferingIdMalformed", (
        f"expected InvalidCapacityBlockOfferingIdMalformed, got {err}"
    )
    assert message == "Capacity Block Offering Id 'not-a-real-offering-id' is malformed.", f"unexpected InvalidCapacityBlockOfferingIdMalformed message: {message!r}"


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
