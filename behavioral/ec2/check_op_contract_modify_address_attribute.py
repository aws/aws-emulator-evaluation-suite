"""op-contract-modify-address-attribute."""
from __future__ import annotations

CHECK = "op-contract-modify-address-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyAddressAttribute sets the reverse-DNS domain on an EIP; unknown AllocationId is rejected."""
    ec2 = ctx.client("ec2")

    # --- error boundary: a syntactically valid but nonexistent AllocationId must be rejected ---
    code, msg = _error(
        lambda: ec2.modify_address_attribute(
            AllocationId="eipalloc-00000000000000000", DomainName="example.com"
        )
    )
    assert code == "InvalidElasticIpID.NotFound", f"unexpected error code: {code!r}"
    expected = "The elasticIp ID 'eipalloc-00000000000000000' does not exist"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # --- success path: allocate a real EIP and set/clear its DomainName attribute ---
    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {
                "ResourceType": "elastic-ip",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-maa-")}],
            }
        ],
    )
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))

    domain = f"{ctx.unique_name('sim2real-eip')}.example.com".lower()
    resp = ec2.modify_address_attribute(AllocationId=allocation_id, DomainName=domain)
    address = resp["Address"]
    assert address["AllocationId"] == allocation_id, (
        f"expected AllocationId {allocation_id!r} echoed in ModifyAddressAttribute's own response, "
        f"got {address!r}"
    )
    assert address["PtrRecord"] == f"{domain}." or address.get("PtrRecordUpdate", {}).get(
        "Value"
    ) == f"{domain}.", f"unexpected address attribute payload: {address!r}"

    def _ptr_value(entry):
        # Real AWS propagates the new PTR record asynchronously: right after ModifyAddressAttribute,
        # PtrRecord still holds the old auto-generated compute.amazonaws.com name and the pending
        # target lives in PtrRecordUpdate.Value (Status "PENDING"). Prefer the pending update;
        # fall back to PtrRecord once it has converged.
        update = entry.get("PtrRecordUpdate") or {}
        return update.get("Value") or entry.get("PtrRecord")

    # The read-side API for this attribute is DescribeAddressesAttribute (plural "Addresses"),
    # not DescribeAddressAttribute. Unlike what the API reference's parameter table implies,
    # real AWS requires the Attribute selector to be supplied explicitly -- without it the call
    # errors out server-side, so pin it to the only valid value: "domain-name".
    described = ec2.describe_addresses_attribute(
        AllocationIds=[allocation_id], Attribute="domain-name"
    )["Addresses"][0]
    assert described["AllocationId"] == allocation_id, (
        f"expected AllocationId {allocation_id!r} in the independent describe read, got {described!r}"
    )
    assert _ptr_value(described) == f"{domain}.", (
        f"expected the independent read to reflect the domain-name just set to {domain!r}, "
        f"got {described!r}"
    )

    # DryRun must reject without touching the attribute
    dry_code, dry_msg = _error(
        lambda: ec2.modify_address_attribute(
            AllocationId=allocation_id, DomainName="other.example.com", DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {dry_msg!r}"

    after_dry_run = ec2.describe_addresses_attribute(
        AllocationIds=[allocation_id], Attribute="domain-name"
    )["Addresses"][0]
    assert _ptr_value(after_dry_run) == f"{domain}.", (
        f"DryRun must not change the domain-name attribute, but the independent read now shows "
        f"{after_dry_run!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
