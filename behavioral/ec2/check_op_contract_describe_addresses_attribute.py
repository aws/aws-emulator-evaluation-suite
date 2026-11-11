"""op-contract-describe-addresses-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-addresses-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddressesAttribute for the domain-name attribute of a newly allocated Elastic IP returns no
    entry on three consecutive reads, and an unknown allocation ID matches no entries instead of
    raising."""
    ec2 = ctx.client("ec2")

    allocation = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=_tags("elastic-ip", ctx.unique_name("sim2real-daa-")),
    )
    allocation_id = allocation["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))

    def _attribute_entries():
        return ec2.describe_addresses_attribute(
            AllocationIds=[allocation_id], Attribute="domain-name"
        )["Addresses"]

    # A never-customized Elastic IP has no domain-name entry: AWS omits the address rather than
    # returning a null PtrRecord, and three reads must all agree.
    first = _attribute_entries()
    assert first == [], f"expected no address-attribute entry for a never-customized EIP, got {first}"
    second = _attribute_entries()
    assert second == [], f"expected the same empty result on a repeat read, got {second}"
    third = _attribute_entries()
    assert third == [], f"expected the same empty result on a third read, got {third}"

    # AllocationIds acts as a filter, not a lookup by ID, so a well-formed never-issued allocation ID
    # matches nothing instead of raising NotFound.
    resp = ec2.describe_addresses_attribute(AllocationIds=["eipalloc-00000000000000000"])
    assert resp.get("Addresses", []) == [], f"expected no entries for unknown allocation id, got {resp}"


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
