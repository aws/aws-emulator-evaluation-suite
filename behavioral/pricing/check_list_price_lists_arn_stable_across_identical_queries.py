"""list-price-lists-arn-stable-across-identical-queries."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-price-lists-arn-stable-across-identical-queries"
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
    """Two ListPriceLists calls with identical parameters resolve to the same set of
    price-list ARNs -- the mapping from (service, date, currency, region) to a price
    list is a deterministic lookup, not a fresh generation each call."""
    pricing = _pricing_client(ctx)
    fixed_effective_date = datetime.now(timezone.utc)
    kwargs = dict(
        ServiceCode="AmazonEC2",
        EffectiveDate=fixed_effective_date,
        CurrencyCode="USD",
        RegionCode="us-east-1",
        MaxResults=5,
    )
    first = pricing.list_price_lists(**kwargs)
    second = pricing.list_price_lists(**kwargs)
    first_arns = sorted(pl["PriceListArn"] for pl in first["PriceLists"])
    second_arns = sorted(pl["PriceListArn"] for pl in second["PriceLists"])
    assert first_arns, "expected at least one price list"
    assert first_arns == second_arns, (
        f"expected identical ARN sets across identical queries, got {first_arns} vs {second_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
