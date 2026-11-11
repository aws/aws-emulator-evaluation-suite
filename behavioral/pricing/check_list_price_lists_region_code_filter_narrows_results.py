"""list-price-lists-region-code-filter-narrows-results."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-price-lists-region-code-filter-narrows-results"
GROUP = "content"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )



@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Filtering ListPriceLists by RegionCode narrows the result set: the unfiltered
    query spans multiple regions, and adding RegionCode excludes every price list
    outside that region rather than merely happening to only contain it."""
    pricing = _pricing_client(ctx)
    now = datetime.now(timezone.utc)

    unfiltered = pricing.list_price_lists(
        ServiceCode="AmazonEC2",
        EffectiveDate=now,
        CurrencyCode="USD",
        MaxResults=100,
    )["PriceLists"]
    unfiltered_regions = {pl["RegionCode"] for pl in unfiltered}
    assert len(unfiltered_regions) > 1, (
        f"expected AmazonEC2 USD price lists spanning multiple regions to prove "
        f"the filter narrows anything, got {unfiltered_regions}"
    )
    other_region_arns = {
        pl["PriceListArn"] for pl in unfiltered if pl["RegionCode"] != "us-east-1"
    }
    assert other_region_arns, "expected at least one non-us-east-1 price list to be excluded"

    filtered = pricing.list_price_lists(
        ServiceCode="AmazonEC2",
        EffectiveDate=now,
        CurrencyCode="USD",
        RegionCode="us-east-1",
        MaxResults=20,
    )["PriceLists"]
    assert filtered, "expected at least one us-east-1 price list"
    for pl in filtered:
        assert pl["RegionCode"] == "us-east-1", pl
    filtered_arns = {pl["PriceListArn"] for pl in filtered}
    assert not (filtered_arns & other_region_arns), (
        f"RegionCode filter did not exclude other-region price lists: "
        f"{filtered_arns & other_region_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
