"""list-services-pagination-returns-distinct-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-services-pagination-returns-distinct-pages"
GROUP = "data-plane"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServices honors MaxResults and NextToken: paging forward returns a
    genuinely different service than the first page."""
    sq = ctx.client("service-quotas")

    page1 = sq.list_services(MaxResults=1)
    assert len(page1["Services"]) == 1, (
        f"expected exactly 1 service with MaxResults=1, got {len(page1['Services'])}"
    )
    assert page1.get("NextToken"), "expected a NextToken with hundreds of AWS services"
    first_code = page1["Services"][0]["ServiceCode"]

    page2 = sq.list_services(MaxResults=1, NextToken=page1["NextToken"])
    assert len(page2["Services"]) == 1, (
        f"expected exactly 1 service with MaxResults=1, got {len(page2['Services'])}"
    )
    second_code = page2["Services"][0]["ServiceCode"]

    assert second_code != first_code, "second page repeated the first page's service"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
