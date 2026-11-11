"""get-products-pricing-terms-include-ondemand-and-reserved."""
from __future__ import annotations

import json

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-products-pricing-terms-include-ondemand-and-reserved"
GROUP = "content"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


_FILTERS = [
    {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
    {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
    {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
    {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
    {"Type": "TERM_MATCH", "Field": "location", "Value": "US East (N. Virginia)"},
    {"Type": "TERM_MATCH", "Field": "instanceType", "Value": "t2.micro"},
]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A standard EC2 compute SKU carries both OnDemand and Reserved pricing terms,
    and each Reserved term is tagged with a real lease contract length."""
    pricing = _pricing_client(ctx)
    resp = pricing.get_products(ServiceCode="AmazonEC2", Filters=_FILTERS, MaxResults=10)
    price_list = [json.loads(item) for item in resp["PriceList"]]
    assert len(price_list) == 1, f"expected exactly 1 matching SKU, got {len(price_list)}"
    terms = price_list[0]["terms"]
    assert "OnDemand" in terms and terms["OnDemand"], f"expected non-empty OnDemand terms, got {terms.get('OnDemand')!r}"
    assert "Reserved" in terms and terms["Reserved"], "expected non-empty Reserved terms"
    reserved_term = next(iter(terms["Reserved"].values()))
    lease_length = reserved_term["termAttributes"]["LeaseContractLength"]
    assert lease_length in {"1yr", "3yr"}, f"expected LeaseContractLength in {{'1yr', '3yr'}}, got {lease_length!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
