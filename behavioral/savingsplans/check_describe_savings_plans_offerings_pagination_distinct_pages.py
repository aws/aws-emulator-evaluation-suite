"""describe-savings-plans-offerings-pagination-distinct-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offerings-pagination-distinct-pages"
GROUP = "pagination"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferings pagination with maxResults=1 returns a nextToken leading to a distinct second page."""
    sp = ctx.client("savingsplans")
    page1 = sp.describe_savings_plans_offerings(planTypes=["Compute"], maxResults=1)
    page1_results = page1["searchResults"]
    assert len(page1_results) == 1, f"expected exactly 1 result for maxResults=1, got {len(page1_results)}"
    token = page1.get("nextToken")
    assert token, "expected a nextToken since Compute offerings exceed a single page of size 1"

    page2 = sp.describe_savings_plans_offerings(planTypes=["Compute"], maxResults=1, nextToken=token)
    page2_results = page2["searchResults"]
    assert len(page2_results) == 1, f"expected exactly 1 result for maxResults=1, got {len(page2_results)}"
    first_id = page1_results[0]["offeringId"]
    second_id = page2_results[0]["offeringId"]
    assert second_id != first_id, f"expected page 2's offering ({second_id}) to differ from page 1's ({first_id})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
