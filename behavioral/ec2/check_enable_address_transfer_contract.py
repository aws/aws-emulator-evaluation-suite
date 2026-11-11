"""enable-address-transfer-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-address-transfer-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableAddressTransfer registers a pending transfer that DescribeAddressTransfers lists once,
    and rejects a nonexistent allocation ID with the allocation-specific NotFound error."""
    ec2 = ctx.client("ec2")

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {
                "ResourceType": "elastic-ip",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eip-")}, {"Key": "sim2real", "Value": "true"}],
            }
        ],
    )
    alloc_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))

    target_account = "111122223333"
    resp = ec2.enable_address_transfer(AllocationId=alloc_id, TransferAccountId=target_account)
    ctx.on_cleanup(lambda: ec2.disable_address_transfer(AllocationId=alloc_id))

    transfer = resp["AddressTransfer"]
    assert transfer["AllocationId"] == alloc_id, f"expected {alloc_id}, got {transfer['AllocationId']!r}"
    assert transfer["TransferAccountId"] == target_account, (
        f"expected {target_account}, got {transfer['TransferAccountId']!r}"
    )
    assert transfer["AddressTransferStatus"] == "pending", (
        f"expected 'pending' immediately after enabling, got {transfer['AddressTransferStatus']!r}"
    )

    described = _await_transfers(ctx, ec2, alloc_id)
    assert len(described) == 1, f"expected exactly one transfer for {alloc_id}, got {len(described)}"
    assert described[0]["TransferAccountId"] == target_account, (
        f"expected {target_account}, got {described[0]['TransferAccountId']!r}"
    )

    # NEGATIVE: a nonexistent allocation ID is rejected with the same allocation-specific
    # NotFound error DisableAddressTransfer uses.
    missing_id = "eipalloc-00000000000000000"
    code, message = _error(lambda: ec2.enable_address_transfer(AllocationId=missing_id, TransferAccountId=target_account))
    assert code == "InvalidElasticIpID.NotFound", f"unexpected error code: {code}"
    assert message == f"The allocation ID '{missing_id}' does not exist", f"unexpected NotFound message: {message!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _await_transfers(ctx, ec2, alloc_id, cap_s=30.0):
    """DescribeAddressTransfers until the eventually consistent read lists a transfer for alloc_id."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        described = ec2.describe_address_transfers(AllocationIds=[alloc_id])["AddressTransfers"]
        if described:
            return described
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s wait ended with no transfer listed for {alloc_id}; not graded"
                )
            return described
        time.sleep(2.0)


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
