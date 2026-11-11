"""list-billing-views-by-type-excludes-primary."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-billing-views-by-type-excludes-primary"
GROUP = "listing"
SERVICES = ["billing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBillingViews filtered to PRIMARY returns exactly one PRIMARY view; filtered to CUSTOM, BILLING_GROUP,
    BILLING_TRANSFER or BILLING_TRANSFER_SHOWBACK it returns only views of that type and never the PRIMARY one;
    filtered to PRIMARY and CUSTOM it returns only those types, with exactly the one PRIMARY view."""
    billing = ctx.client("billing")

    primary_views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(primary_views) == 1, f"expected exactly one PRIMARY billing view, got {len(primary_views)}"
    primary = primary_views[0]
    assert primary["billingViewType"] == "PRIMARY", primary["billingViewType"]

    for other_type in ("CUSTOM", "BILLING_GROUP", "BILLING_TRANSFER", "BILLING_TRANSFER_SHOWBACK"):
        views = billing.list_billing_views(billingViewTypes=[other_type])["billingViews"]
        assert all(v["billingViewType"] == other_type for v in views), (
            f"billingViewTypes=[{other_type}] returned a view of a different type: {views}"
        )
        assert primary["arn"] not in [v["arn"] for v in views], (
            f"PRIMARY view {primary['arn']} leaked into the {other_type}-only filter: {views}"
        )

    union = billing.list_billing_views(billingViewTypes=["PRIMARY", "CUSTOM"])["billingViews"]
    assert all(v["billingViewType"] in ("PRIMARY", "CUSTOM") for v in union), (
        f"billingViewTypes=[PRIMARY, CUSTOM] returned a view of another type: {union}"
    )
    union_primary = [v["arn"] for v in union if v["billingViewType"] == "PRIMARY"]
    assert union_primary == [primary["arn"]], (
        f"billingViewTypes=[PRIMARY, CUSTOM] expected exactly the PRIMARY view {primary['arn']} "
        f"among its PRIMARY views, got {union_primary}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

