"""op-contract-describe-address-transfers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-address-transfers"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddressTransfers scoped to an allocation with no transfer returns none, scoped to one with
    a pending transfer returns exactly that transfer, and unscoped includes it; DryRun answers
    DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    idle = ec2.allocate_address(Domain="vpc")
    idle_id = idle["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=idle_id))

    pending = ec2.allocate_address(Domain="vpc")
    pending_id = pending["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=pending_id))
    ec2.enable_address_transfer(AllocationId=pending_id, TransferAccountId="111122223333")
    ctx.on_cleanup(lambda: ec2.disable_address_transfer(AllocationId=pending_id))

    # scoping: the idle allocation's own transfer set is empty even though a sibling
    # allocation in the same account has a pending transfer right now
    resp = ec2.describe_address_transfers(AllocationIds=[idle_id])
    assert resp["AddressTransfers"] == [], f"expected no pending transfer for {idle_id}, got {resp['AddressTransfers']}"

    # scoping the other way: querying the allocation that does have a transfer returns
    # exactly it, proving the AllocationIds filter actually filters rather than always
    # returning everything (or always returning nothing)
    scoped = ec2.describe_address_transfers(AllocationIds=[pending_id])["AddressTransfers"]
    assert len(scoped) == 1, f"expected exactly one transfer for {pending_id}, got {scoped}"
    assert scoped[0]["AllocationId"] == pending_id, f"expected {pending_id}, got {scoped[0]}"

    # unscoped call must aggregate across the account and surface the pending transfer,
    # not just return an empty list by default
    unscoped = ec2.describe_address_transfers()["AddressTransfers"]
    assert any(t["AllocationId"] == pending_id for t in unscoped), (
        f"expected {pending_id}'s transfer in the unscoped result, got {unscoped}"
    )

    # error boundary: DryRun performs the permission check without returning data
    code, code_msg = _error(lambda: ec2.describe_address_transfers(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
