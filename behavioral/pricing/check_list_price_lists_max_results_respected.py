"""list-price-lists-max-results-respected."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-price-lists-max-results-respected"
GROUP = "pagination"
SERVICES = ["pricing"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPriceLists honors MaxResults=1, and its NextToken leads to a page with a different
    price-list ARN (the client is pinned to us-east-1, a Price List API region)."""
    pricing = ctx.client("pricing", region="us-east-1")
    now = datetime.now(timezone.utc)
    first = pricing.list_price_lists(ServiceCode="AmazonEC2", EffectiveDate=now, CurrencyCode="USD", MaxResults=1)
    assert len(first["PriceLists"]) == 1, f"expected exactly 1 price list, got {len(first['PriceLists'])}"
    token = first.get("NextToken")
    assert token, "expected more than one AmazonEC2 USD price list"

    second = pricing.list_price_lists(
        ServiceCode="AmazonEC2", EffectiveDate=now, CurrencyCode="USD", MaxResults=1, NextToken=token
    )
    assert len(second["PriceLists"]) == 1, f"expected exactly 1 price list, got {len(second['PriceLists'])}"
    first_arn = first["PriceLists"][0]["PriceListArn"]
    second_arn = second["PriceLists"][0]["PriceListArn"]
    assert first_arn != second_arn, f"expected a distinct ARN on page 2, got the same one: {first_arn}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
