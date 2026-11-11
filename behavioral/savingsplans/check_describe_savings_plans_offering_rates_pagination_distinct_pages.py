"""describe-savings-plans-offering-rates-pagination-distinct-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offering-rates-pagination-distinct-pages"
GROUP = "pagination"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferingRates pagination with maxResults=1 returns a nextToken leading to a distinct second page."""
    sp = ctx.client("savingsplans")
    page1 = sp.describe_savings_plans_offering_rates(savingsPlanTypes=["Compute"], maxResults=1)
    assert len(page1["searchResults"]) == 1, (
        f"expected maxResults=1 to cap page1 at 1 result, got {len(page1['searchResults'])}"
    )
    token = page1.get("nextToken")
    assert token, "expected a nextToken since Compute offering rates exceed a single page of size 1"

    page2 = sp.describe_savings_plans_offering_rates(
        savingsPlanTypes=["Compute"], maxResults=1, nextToken=token
    )
    assert len(page2["searchResults"]) == 1, (
        f"expected maxResults=1 to cap page2 at 1 result, got {len(page2['searchResults'])}"
    )
    first = page1["searchResults"][0]
    second = page2["searchResults"][0]
    assert (
        first["savingsPlanOffering"]["offeringId"] != second["savingsPlanOffering"]["offeringId"]
        or first["usageType"] != second["usageType"]
    ), (
        f"expected page2 to advance past page1's item, got the same "
        f"offeringId={second['savingsPlanOffering']['offeringId']!r} usageType={second['usageType']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
