"""op-contract-delete-queued-reserved-instances-standalone-rejection."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "op-contract-delete-queued-reserved-instances-standalone-rejection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQueuedReservedInstances on two never-queued Reserved Instances IDs reports each exactly once
    as a failed deletion with reserved-instances-id-invalid and neither as successfully deleted."""
    ec2 = ctx.client("ec2")
    bogus_ids = [str(uuid.uuid4()), str(uuid.uuid4())]

    resp = ec2.delete_queued_reserved_instances(ReservedInstancesIds=bogus_ids)

    successful = resp.get("SuccessfulQueuedPurchaseDeletionSet", resp.get("SuccessfulQueuedPurchaseDeletions", []))
    failed = resp.get("FailedQueuedPurchaseDeletionSet", resp.get("FailedQueuedPurchaseDeletions", []))

    assert not any(
        s.get("ReservedInstancesId") in bogus_ids for s in successful
    ), f"a never-queued Reserved Instances ID must not report as successfully deleted: {successful}"

    for bogus_id in bogus_ids:
        matches = [f for f in failed if f.get("ReservedInstancesId") == bogus_id]
        assert len(matches) == 1, f"expected exactly one failure entry for {bogus_id}, got {failed}"
        assert (
            matches[0]["Error"]["Code"] == "reserved-instances-id-invalid"
        ), f"unexpected error code for {bogus_id}: {matches[0]['Error']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
