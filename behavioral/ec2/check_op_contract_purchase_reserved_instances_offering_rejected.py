"""op-contract-purchase-reserved-instances-offering-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-purchase-reserved-instances-offering-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedInstancesOffering with DryRun fails with DryRunOperation and the standard message;
    without DryRun a malformed offering id fails with InvalidParameterValue and its exact message, and
    DescribeReservedInstances lists as many reservations afterwards as before."""
    ec2 = ctx.client("ec2")

    well_formed_but_nonexistent = str(uuid.uuid4())
    before = ec2.describe_reserved_instances()["ReservedInstances"]

    control_err = _client_error(
        lambda: ec2.purchase_reserved_instances_offering(
            ReservedInstancesOfferingId=well_formed_but_nonexistent, InstanceCount=1, DryRun=True
        )
    )
    assert control_err.get("Code") == "DryRunOperation", (
        f"a well-formed offering id should clear shape validation and reach the dry-run gate, "
        f"got {control_err.get('Code')!r}"
    )
    assert control_err.get("Message") == _DRY_RUN_MESSAGE, (
        f"unexpected DryRunOperation message {control_err.get('Message')!r}"
    )

    err = _client_error(
        lambda: ec2.purchase_reserved_instances_offering(
            ReservedInstancesOfferingId="not-a-real-offering-id", InstanceCount=1
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {err.get('Code')!r}"
    )
    assert err.get("Message") == (
        "Invalid value 'ReservedInstancesOfferingId' for not-a-real-offering-id."
    ), f"unexpected InvalidParameterValue message {err.get('Message')!r}"

    after = ec2.describe_reserved_instances()["ReservedInstances"]
    assert len(after) == len(before), (
        f"neither the dry-run control nor the rejected call should purchase anything: "
        f"{len(before)} reserved instances before, {len(after)} after"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
