"""describe-savings-plans-offering-rates-filtered-by-product-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offering-rates-filtered-by-product-type"
GROUP = "control-plane"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferingRates 'products' filter restricts every returned rate to that product type."""
    sp = ctx.client("savingsplans")

    fargate = sp.describe_savings_plans_offering_rates(
        savingsPlanTypes=["Compute"],
        products=["Fargate"],
        maxResults=20,
    )
    fargate_results = fargate["searchResults"]
    assert len(fargate_results) > 0, "expected at least one Fargate rate under a Compute Savings Plan"
    for rate in fargate_results:
        assert rate["productType"] == "Fargate", f"products=['Fargate'] filter leaked a {rate['productType']!r} rate"

    resp = sp.describe_savings_plans_offering_rates(
        savingsPlanTypes=["Compute"],
        products=["EC2"],
        maxResults=20,
    )
    results = resp["searchResults"]
    assert len(results) > 0, "expected at least one EC2 rate under a Compute Savings Plan"
    for rate in results:
        assert rate["productType"] == "EC2", f"products=['EC2'] filter leaked a {rate['productType']!r} rate"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
