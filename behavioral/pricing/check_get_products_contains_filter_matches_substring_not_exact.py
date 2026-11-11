"""get-products-contains-filter-matches-substring-not-exact."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-products-contains-filter-matches-substring-not-exact"
GROUP = "content"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is served only from us-east-1, eu-central-1 and ap-south-1, so
    the client is pinned to us-east-1 through ctx, which keeps the target's endpoint and creds."""
    from botocore.config import Config

    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CONTAINS filter matches the field as a substring, returning values that are
    not equal to the filter value itself (unlike TERM_MATCH's exact-match semantics)."""
    pricing = _pricing_client(ctx)
    resp = pricing.get_products(
        ServiceCode="AmazonEC2",
        Filters=[{"Type": "CONTAINS", "Field": "volumeType", "Value": "HDD"}],
        MaxResults=20,
    )
    price_list = [json.loads(item) for item in resp["PriceList"]]
    assert price_list, "expected at least one HDD volume product"
    volume_types = {p["product"]["attributes"]["volumeType"] for p in price_list}
    for vt in volume_types:
        assert "HDD" in vt, f"CONTAINS filter on volumeType='HDD' returned non-matching value {vt!r}"
    assert any(vt != "HDD" for vt in volume_types), (
        f"expected at least one substring match distinct from the exact value 'HDD', got only {volume_types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
