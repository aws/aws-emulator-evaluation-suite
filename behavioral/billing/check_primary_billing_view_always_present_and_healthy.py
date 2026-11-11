"""primary-billing-view-always-present-and-healthy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "primary-billing-view-always-present-and-healthy"
GROUP = "lifecycle"
SERVICES = ["billing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every AWS account has exactly one PRIMARY billing view, it is always
    HEALTHY, has no configured source views, and is owned by the caller's
    own account."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(views) == 1, f"expected exactly one PRIMARY billing view, got {len(views)}"
    listed = views[0]
    assert listed["billingViewType"] == "PRIMARY", (
        f"expected billingViewType PRIMARY under a PRIMARY-type filter, got {listed['billingViewType']!r}"
    )
    assert listed["healthStatus"]["statusCode"] == "HEALTHY", (
        f"expected the listed PRIMARY view HEALTHY, got {listed['healthStatus']['statusCode']!r}"
    )

    detail = billing.get_billing_view(arn=listed["arn"])["billingView"]
    assert detail["billingViewType"] == "PRIMARY", (
        f"expected GetBillingView on the listed PRIMARY arn to echo PRIMARY, got {detail['billingViewType']!r}"
    )
    assert detail["ownerAccountId"] == account_id, (
        f"expected the PRIMARY view owned by the caller's own account {account_id!r}, got {detail['ownerAccountId']!r}"
    )
    # sourceViewCount is only populated for CUSTOM-type views on some accounts;
    # PRIMARY views may omit it entirely rather than report 0 explicitly.
    assert detail.get("sourceViewCount", 0) == 0, (
        f"expected no source views configured on the PRIMARY view, got sourceViewCount={detail.get('sourceViewCount')!r}"
    )
    assert detail["healthStatus"]["statusCode"] == "HEALTHY", (
        f"expected the detailed PRIMARY view HEALTHY, got {detail['healthStatus']['statusCode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
