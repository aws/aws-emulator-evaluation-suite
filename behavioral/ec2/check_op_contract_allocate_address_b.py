"""op-contract-allocateAddress-b."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-allocateAddress-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AllocateAddress returns an eipalloc- id and a public IPv4; an unowned specific Address is
    rejected with InvalidAddress.NotFound, and the released id is NotFound on read and release.
    Each error must carry a Message and a RequestId."""
    ec2 = ctx.client("ec2")

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: _release_if_present(ec2, allocation_id))

    assert allocation_id.startswith("eipalloc-"), allocation_id
    assert alloc["Domain"] == "vpc"
    assert _IPV4_RE.match(alloc["PublicIp"]), alloc["PublicIp"]

    described = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
    assert described["PublicIp"] == alloc["PublicIp"]
    assert described["Domain"] == "vpc"

    # EC2 treats an unowned address as a not-found lookup, not a parameter-format error.
    message = _expect_client_error(
        lambda: ec2.allocate_address(Domain="vpc", Address="192.0.2.88"),
        "InvalidAddress.NotFound",
    )
    assert message == "The Elastic IP address '192.0.2.88' does not exist or is not available.", (
        message
    )

    ec2.release_address(AllocationId=allocation_id)
    gone = f"The allocation ID '{allocation_id}' does not exist"
    message = _expect_client_error(
        lambda: ec2.describe_addresses(AllocationIds=[allocation_id]),
        "InvalidAllocationID.NotFound",
    )
    assert message == gone, message
    message = _expect_client_error(
        lambda: ec2.release_address(AllocationId=allocation_id),
        "InvalidAllocationID.NotFound",
    )
    assert message == gone, message


def _release_if_present(ec2, allocation_id: str) -> None:
    """Release the address unless it is already gone."""
    try:
        ec2.release_address(AllocationId=allocation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAllocationID.NotFound":
            raise


def _expect_client_error(fn, expected_code: str) -> str:
    """Assert fn() raises expected_code with a RequestId; return the error message."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == expected_code, f"expected {expected_code}, got {err['Code']!r}"
        assert exc.response.get("ResponseMetadata", {}).get("RequestId"), (
            "expected a RequestId in ResponseMetadata"
        )
        return err.get("Message")
    raise AssertionError(f"expected ClientError {expected_code!r}, call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
