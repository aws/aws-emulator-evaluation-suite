"""update-reputation-entity-customer-managed-status-stale-conflict-rejected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-reputation-entity-customer-managed-status-stale-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing DISABLED/ENABLED customer-managed status updates: any loser fails ConflictException,
    one write lands, status reads DISABLED or ENABLED; solo updates read back DISABLED, REINSTATED.
    """
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    tenant = sesv2.create_tenant(
        TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": tenant_name}]
    )
    tenant_arn = tenant["TenantArn"]
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))

    baseline = _get_entity(sesv2, tenant_arn)
    # a freshly created entity has no explicit customer-managed status record yet;
    # its effective status is ENABLED either way
    baseline_status = baseline.get("CustomerManagedStatus", {}).get("Status", "ENABLED")
    assert baseline_status == "ENABLED", f"expected fresh entity ENABLED, got {baseline_status}"

    barrier = threading.Barrier(2)

    def _apply(status: str) -> tuple[str, str | None]:
        barrier.wait(timeout=10)
        try:
            sesv2.update_reputation_entity_customer_managed_status(
                ReputationEntityType="RESOURCE",
                ReputationEntityReference=tenant_arn,
                SendingStatus=status,
            )
            return ("ok", None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(_apply, ["DISABLED", "ENABLED"]))

    outcomes = [r[0] for r in results]
    errors = [r[1] for r in results if r[0] == "error"]
    for code in errors:
        assert code == "ConflictException", f"loser raised {code}, not ConflictException (results={results})"
    assert outcomes.count("ok") >= 1, f"expected at least one winner, got {results}"

    raced = _get_entity(sesv2, tenant_arn)
    raced_status = raced.get("CustomerManagedStatus", {}).get("Status")
    assert raced_status in ("DISABLED", "ENABLED"), (
        f"status corrupted by the race: expected DISABLED or ENABLED, got {raced_status}"
    )

    sesv2.update_reputation_entity_customer_managed_status(
        ReputationEntityType="RESOURCE",
        ReputationEntityReference=tenant_arn,
        SendingStatus="DISABLED",
    )
    disabled = _get_entity(sesv2, tenant_arn)
    disabled_status = disabled["CustomerManagedStatus"]["Status"]
    assert disabled_status == "DISABLED", f"expected DISABLED, got {disabled_status}"

    sesv2.update_reputation_entity_customer_managed_status(
        ReputationEntityType="RESOURCE",
        ReputationEntityReference=tenant_arn,
        SendingStatus="REINSTATED",
    )
    reinstated = _get_entity(sesv2, tenant_arn)
    reinstated_status = reinstated["CustomerManagedStatus"]["Status"]
    assert reinstated_status == "REINSTATED", f"expected REINSTATED, got {reinstated_status}"


def _get_entity(sesv2, reference: str) -> dict:
    return sesv2.get_reputation_entity(
        ReputationEntityType="RESOURCE", ReputationEntityReference=reference
    )["ReputationEntity"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
