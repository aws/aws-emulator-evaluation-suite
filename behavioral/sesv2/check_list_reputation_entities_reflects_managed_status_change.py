"""list-reputation-entities-reflects-managed-status-change."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-reputation-entities-reflects-managed-status-change"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateReputationEntityCustomerManagedStatus disables an entity,
    ListReputationEntities (filtered down to that entity) reflects the new
    CustomerManagedStatus rather than the stale, previously-listed ENABLED value."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    tenant = sesv2.create_tenant(TenantName=tenant_name)
    tenant_arn = tenant["TenantArn"]
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))

    before = _poll_until(
        lambda: sesv2.list_reputation_entities(
            Filter={"ENTITY_REFERENCE_PREFIX": tenant_arn}
        )["ReputationEntities"],
        lambda entities: len(entities) == 1,
    )
    assert len(before) == 1, f"expected exactly 1 reputation entity, got {before}"
    assert before[0]["ReputationEntityReference"] == tenant_arn, (
        f"expected reference {tenant_arn}, got {before[0]['ReputationEntityReference']}"
    )
    # a freshly created entity has no explicit customer-managed status record yet;
    # its effective status is ENABLED either way
    before_status = before[0].get("CustomerManagedStatus", {}).get("Status", "ENABLED")
    assert before_status == "ENABLED", f"expected ENABLED before any update, got {before_status}"

    sesv2.update_reputation_entity_customer_managed_status(
        ReputationEntityType="RESOURCE",
        ReputationEntityReference=tenant_arn,
        SendingStatus="DISABLED",
    )

    after = _poll_until(
        lambda: sesv2.list_reputation_entities(
            Filter={"ENTITY_REFERENCE_PREFIX": tenant_arn}
        )["ReputationEntities"],
        lambda entities: len(entities) == 1
        and entities[0]["CustomerManagedStatus"]["Status"] == "DISABLED",
    )
    assert len(after) == 1, f"expected exactly 1 reputation entity after update, got {after}"
    assert after[0]["ReputationEntityReference"] == tenant_arn, (
        f"expected reference {tenant_arn}, got {after[0]['ReputationEntityReference']}"
    )
    assert after[0]["CustomerManagedStatus"]["Status"] == "DISABLED", (
        f"expected ListReputationEntities to reflect DISABLED, got {after[0]['CustomerManagedStatus']['Status']}"
    )


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
