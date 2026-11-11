"""op-contract-reset-address-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-reset-address-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResetAddressAttribute fails with InvalidAllocationID.NotFound "No ptr record found" for an address
    with no custom PTR, with PendingRequestAlreadyExists for one whose PTR change is pending, and with
    InvalidAllocationID.NotFound "does not exist" for an unknown allocation id (exact messages)."""
    ec2 = ctx.client("ec2")

    # --- never customized: nothing to revert ---
    alloc = ec2.allocate_address(
        Domain="vpc", TagSpecifications=_tags("elastic-ip", ctx.unique_name("sim2real-raa-")),
    )
    alloc_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))

    code, message = _error_code_and_message(lambda: ec2.reset_address_attribute(
        AllocationId=alloc_id, Attribute="domain-name"))
    assert code == "InvalidAllocationID.NotFound", (
        f"expected InvalidAllocationID.NotFound for a never-customized domain-name, got {code}")
    assert message == f"No ptr record found for {alloc['PublicIp']} .", (
        f"unexpected message for the never-customized case: {message!r}")

    # --- customization in flight (unconfirmed): a pending verification request blocks reset
    # with a distinct code, proving the rejection tracks real per-address state ---
    alloc_pending = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=_tags("elastic-ip", ctx.unique_name("sim2real-raa-pending-")),
    )
    pending_id = alloc_pending["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=pending_id))
    pending_domain = f"{ctx.unique_name('sim2real-raa-ptr')}.example.com".lower()
    ec2.modify_address_attribute(AllocationId=pending_id, DomainName=pending_domain)

    code_pending, message_pending = _error_code_and_message(lambda: ec2.reset_address_attribute(
        AllocationId=pending_id, Attribute="domain-name"))
    assert code_pending == "PendingRequestAlreadyExists", (
        f"expected PendingRequestAlreadyExists for a reset while a customization is pending, "
        f"got {code_pending}")
    assert message_pending == "A pending request for this record already exists.", (
        f"unexpected message for the in-flight case: {message_pending!r}")

    # --- unknown allocation id: same top-level code as the never-customized case, but a
    # distinct message ---
    code2, message2 = _error_code_and_message(lambda: ec2.reset_address_attribute(
        AllocationId="eipalloc-1234567890abcdef0", Attribute="domain-name"))
    assert code2 == "InvalidAllocationID.NotFound", (
        f"expected InvalidAllocationID.NotFound for an unknown allocation, got {code2}")
    assert message2 == "The allocation ID 'eipalloc-1234567890abcdef0' does not exist", (
        f"unexpected message for an unknown allocation: {message2!r}")


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error_code_and_message(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
