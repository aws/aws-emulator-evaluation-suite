"""op-contract-describe-addresses."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-addresses"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddresses reflects a freshly allocated EIP by AllocationId and
    by tag filter; an unknown allocation id 404s distinctly from a malformed one."""
    ec2 = ctx.client("ec2")

    tag_value = ctx.unique_name("sim2real-behav-eip-")
    allocation = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {"ResourceType": "elastic-ip", "Tags": [{"Key": "Name", "Value": tag_value}]}
        ],
    )
    allocation_id = allocation["AllocationId"]
    public_ip = allocation["PublicIp"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))

    # success path: lookup by allocation id returns exactly this address, in-vpc
    by_id = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"]
    assert len(by_id) == 1, f"expected exactly 1 address, got {len(by_id)}"
    assert by_id[0]["PublicIp"] == public_ip, (
        f"expected PublicIp {public_ip!r}, got {by_id[0]['PublicIp']!r}"
    )
    assert by_id[0]["Domain"] == "vpc", f"expected Domain 'vpc', got {by_id[0]['Domain']!r}"

    # success path: lookup by tag filter finds the same address
    by_tag = ec2.describe_addresses(Filters=[{"Name": "tag:Name", "Values": [tag_value]}])["Addresses"]
    assert len(by_tag) == 1 and by_tag[0]["AllocationId"] == allocation_id, (
        f"tag filter did not resolve to the expected address: {by_tag}"
    )

    # error boundary: a well-formed but never-issued allocation id 404s
    code, message = _error_of(lambda: ec2.describe_addresses(AllocationIds=["eipalloc-00000000000000000"]))
    assert code == "InvalidAllocationID.NotFound", f"expected InvalidAllocationID.NotFound, got {code}"
    assert message == "The allocation ID 'eipalloc-00000000000000000' does not exist", message


def _error_of(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
