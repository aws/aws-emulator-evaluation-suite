"""op-contract-describeCapacityBlockOfferings."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeCapacityBlockOfferings"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityBlockOfferings requires CapacityDurationHours and returns the offering shape."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_block_offerings")

    # success path: CapacityDurationHours is required, and the API additionally requires
    # either (InstanceType + InstanceCount) or (UltraserverType + UltraserverCount) to be
    # specified together with it; a search that finds no matching offering still returns a
    # well-formed 200 with an (possibly empty) list.
    response = ec2.describe_capacity_block_offerings(
        CapacityDurationHours=24, InstanceType="p4d.24xlarge", InstanceCount=1
    )
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert "CapacityBlockOfferings" in response
    assert isinstance(response["CapacityBlockOfferings"], list)

    # error boundary: CapacityDurationHours is the only member botocore's local model marks
    # required, so pairing it with neither (InstanceType+InstanceCount) nor
    # (UltraserverType+UltraserverCount) never raises ParamValidationError -- the SDK ships the
    # request, and the service rejects it server-side.
    try:
        ec2.describe_capacity_block_offerings(CapacityDurationHours=24)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message!r})"
        assert message == (
            "Invalid inputs, either ultraserver-type and ultraserver-count, or instance-type and "
            "instance-count needs to be set, not both"
        ), f"unexpected InvalidParameterValue message {message!r}"
    else:
        raise AssertionError(
            "describe_capacity_block_offerings(CapacityDurationHours=24) with no "
            "instance/ultraserver selector unexpectedly succeeded"
        )


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
