"""get-products-term-match-filters-return-single-matching-product."""
from __future__ import annotations

import json

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-products-term-match-filters-return-single-matching-product"
GROUP = "content"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


_BASE_FILTERS = [
    {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
    {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
    {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
    {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
    {"Type": "TERM_MATCH", "Field": "location", "Value": "US East (N. Virginia)"},
]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProducts with a fully-qualified TERM_MATCH filter set identifies exactly one
    EC2 on-demand SKU, and its OnDemand price dimension carries a positive USD rate."""
    pricing = _pricing_client(ctx)
    filters = _BASE_FILTERS + [{"Type": "TERM_MATCH", "Field": "instanceType", "Value": "t2.micro"}]
    resp = pricing.get_products(ServiceCode="AmazonEC2", Filters=filters, MaxResults=10)
    price_list = [json.loads(item) for item in resp["PriceList"]]
    assert len(price_list) == 1, f"expected exactly 1 matching SKU, got {len(price_list)}"
    product = price_list[0]
    attrs = product["product"]["attributes"]
    assert attrs["instanceType"] == "t2.micro", f"expected instanceType t2.micro, got {attrs['instanceType']}"
    assert attrs["location"] == "US East (N. Virginia)", f"expected US East (N. Virginia), got {attrs['location']}"
    assert attrs["operatingSystem"] == "Linux", f"expected operatingSystem Linux, got {attrs['operatingSystem']}"
    on_demand_terms = product["terms"]["OnDemand"]
    (term,) = on_demand_terms.values()
    (dimension,) = term["priceDimensions"].values()
    rate = float(dimension["pricePerUnit"]["USD"])
    assert rate > 0, f"expected a positive USD on-demand rate, got {rate}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
