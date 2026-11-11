"""op-contract-delete-queued-reserved-instances."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "op-contract-delete-queued-reserved-instances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQueuedReservedInstances on a Reserved Instances ID that was never queued raises nothing and
    reports that ID as one failed deletion with reserved-instances-id-invalid and no successful one."""
    ec2 = ctx.client("ec2")
    bogus_ri_id = str(uuid.uuid4())

    resp = ec2.delete_queued_reserved_instances(ReservedInstancesIds=[bogus_ri_id])

    successes = resp.get("SuccessfulQueuedPurchaseDeletionSet", resp.get("SuccessfulQueuedPurchaseDeletions", []))
    failures = resp.get("FailedQueuedPurchaseDeletionSet", resp.get("FailedQueuedPurchaseDeletions", []))

    assert successes == [], f"unexpected success for an ID that was never queued: {successes}"
    assert len(failures) == 1, f"expected exactly one failure entry, got: {failures}"
    failure = failures[0]
    assert failure["ReservedInstancesId"] == bogus_ri_id, (
        f"failure entry ReservedInstancesId mismatch: expected {bogus_ri_id!r}, got {failure.get('ReservedInstancesId')!r}"
    )
    assert failure["Error"]["Code"] == "reserved-instances-id-invalid", f"unexpected error code: {failure['Error']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
