"""op-contract-disable-address-transfer."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-address-transfer"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableAddressTransfer: success cancels a pending Elastic IP transfer, returning the
    AddressTransfer with status 'disabled'; a bogus AllocationId is rejected with the
    specific InvalidElasticIpID.NotFound error."""
    ec2 = ctx.client("ec2")

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=_tag_spec(ctx, "elastic-ip", ctx.unique_name("sim2real-eip-")),
    )
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))

    # A documentation placeholder account as the transfer target.
    target_account_id = "111122223333"

    ec2.enable_address_transfer(AllocationId=allocation_id, TransferAccountId=target_account_id)
    ctx.on_cleanup(lambda: _best_effort_disable(ec2, allocation_id))

    transfer = ec2.disable_address_transfer(AllocationId=allocation_id)["AddressTransfer"]
    assert transfer["AllocationId"] == allocation_id, transfer
    assert transfer["AddressTransferStatus"] == "disabled", transfer

    # independent read at a different operation: disabling clears the transfer record
    # entirely (real AWS does not keep a lingering "disabled" entry), so it must no
    # longer show up as a pending/active transfer for this allocation.
    described = ec2.describe_address_transfers(AllocationIds=[allocation_id])["AddressTransfers"]
    assert described == [], f"expected no transfer after disable, got {described}"

    code, message = _client_error(
        lambda: ec2.disable_address_transfer(AllocationId="eipalloc-00000000000000000")
    )
    assert code == "InvalidElasticIpID.NotFound", code
    expected_message = "The allocation ID 'eipalloc-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _best_effort_disable(ec2, allocation_id):
    try:
        ec2.disable_address_transfer(AllocationId=allocation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidElasticIpID.NotFound":
            raise


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
