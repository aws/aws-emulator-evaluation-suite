"""op-contract-allocateAddress."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-allocateAddress"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AllocateAddress returns a vpc-domain eipalloc- id and public IPv4 that DescribeAddresses
    agrees with; requesting the unowned 192.0.2.55 fails InvalidAddress.NotFound, and after release
    both a describe and a second release fail InvalidAllocationID.NotFound, with exact messages.
    """
    ec2 = ctx.client("ec2")

    tag_value = ctx.unique_name("sim2real-behav-eip-")
    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {"ResourceType": "elastic-ip", "Tags": [{"Key": "Name", "Value": tag_value}]}
        ],
    )
    allocation_id = alloc["AllocationId"]

    def _cleanup():
        try:
            ec2.release_address(AllocationId=allocation_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAllocationID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    assert allocation_id.startswith("eipalloc-"), f"expected an eipalloc- id, got {allocation_id!r}"
    assert alloc["Domain"] == "vpc", f"expected Domain vpc, got {alloc['Domain']!r}"
    assert _IPV4_RE.match(alloc["PublicIp"]), f"expected a dotted IPv4, got {alloc['PublicIp']!r}"

    described = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
    assert described["PublicIp"] == alloc["PublicIp"], (
        f"expected describe to echo {alloc['PublicIp']!r}, got {described['PublicIp']!r}"
    )
    assert described["Domain"] == "vpc", f"expected Domain vpc, got {described['Domain']!r}"

    # distinct error boundary: a specific address outside every owned address pool is
    # rejected as an address-not-found lookup, not a parameter-format error.
    code, message = _error_of(lambda: ec2.allocate_address(Domain="vpc", Address="192.0.2.55"))
    assert code == "InvalidAddress.NotFound", f"expected InvalidAddress.NotFound, got {code!r}"
    assert message == "The Elastic IP address '192.0.2.55' does not exist or is not available.", (
        f"AllocateAddress(Address='192.0.2.55') message: {message!r}"
    )

    # deletes prove gone and unusable: an independent read 404s, and a second
    # release on the same dead id 404s with the identical specific code.
    ec2.release_address(AllocationId=allocation_id)

    gone = f"The allocation ID '{allocation_id}' does not exist"
    code, message = _error_of(lambda: ec2.describe_addresses(AllocationIds=[allocation_id]))
    assert code == "InvalidAllocationID.NotFound", (
        f"expected released allocation to 404 on describe, got {code!r}"
    )
    assert message == gone, f"DescribeAddresses message for released {allocation_id}: {message!r}"

    code, message = _error_of(lambda: ec2.release_address(AllocationId=allocation_id))
    assert code == "InvalidAllocationID.NotFound", (
        f"expected a second release of the same allocation to 404, got {code!r}"
    )
    assert message == gone, f"second ReleaseAddress message for {allocation_id}: {message!r}"


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
