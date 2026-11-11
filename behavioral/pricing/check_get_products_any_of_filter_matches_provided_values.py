"""get-products-any-of-filter-matches-provided-values."""
from __future__ import annotations

import json

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-products-any-of-filter-matches-provided-values"
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
    """An ANY_OF filter returns exactly the SKUs whose field matches one of the
    comma-separated candidate values -- no more, no fewer."""
    pricing = _pricing_client(ctx)
    filters = _BASE_FILTERS + [
        {"Type": "ANY_OF", "Field": "instanceType", "Value": "t2.micro,t2.small,t2.medium"}
    ]
    resp = pricing.get_products(ServiceCode="AmazonEC2", Filters=filters, MaxResults=20)
    price_list = [json.loads(item) for item in resp["PriceList"]]
    found_types = {p["product"]["attributes"]["instanceType"] for p in price_list}
    expected_types = {"t2.micro", "t2.small", "t2.medium"}
    assert found_types == expected_types, f"expected {expected_types}, got {found_types}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
