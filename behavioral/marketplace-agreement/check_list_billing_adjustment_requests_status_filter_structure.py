"""list-billing-adjustment-requests-status-filter-structure."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "list-billing-adjustment-requests-status-filter-structure"
GROUP = "list-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBillingAdjustmentRequests accepts every documented BillingAdjustmentStatus filter
    value (PENDING, VALIDATION_FAILED, COMPLETED) without error, each returning a bounded,
    well-formed page -- proving the enum is fully wired up server-side, not just partially."""
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    for status in ("PENDING", "VALIDATION_FAILED", "COMPLETED"):
        resp = mpa.list_billing_adjustment_requests(status=status, maxResults=3)
        items = resp["items"]
        assert isinstance(items, list), f"items was not a list for status={status}"
        assert len(items) <= 3, f"maxResults=3 but got {len(items)} items for status={status}"
        for item in items:
            assert item["status"] == status, (
                f"requested status={status} but item "
                f"{item['billingAdjustmentRequestId']!r} reported status={item['status']!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
