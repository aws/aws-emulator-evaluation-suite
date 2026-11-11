"""get-products-none-of-filter-excludes-value."""
from __future__ import annotations

import json

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-products-none-of-filter-excludes-value"
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
    """A TERM_MATCH filter proves the t2.micro SKU exists under the base constraints;
    a NONE_OF filter on the same field then excludes it from the returned page."""
    pricing = _pricing_client(ctx)
    control = pricing.get_products(
        ServiceCode="AmazonEC2",
        Filters=_BASE_FILTERS + [{"Type": "TERM_MATCH", "Field": "instanceType", "Value": "t2.micro"}],
        MaxResults=10,
    )
    assert len(control["PriceList"]) == 1, "positive control: t2.micro SKU must exist"

    excluded = pricing.get_products(
        ServiceCode="AmazonEC2",
        Filters=_BASE_FILTERS + [{"Type": "NONE_OF", "Field": "instanceType", "Value": "t2.micro"}],
        MaxResults=100,
    )
    instance_types = {
        json.loads(item)["product"]["attributes"]["instanceType"] for item in excluded["PriceList"]
    }
    assert instance_types, "expected other instance types to remain"
    assert "t2.micro" not in instance_types, (
        f"NONE_OF instanceType=t2.micro must exclude it, got instance types: {sorted(instance_types)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
