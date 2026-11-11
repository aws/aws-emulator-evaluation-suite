"""list-price-lists-returns-arn-and-supported-file-formats."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-price-lists-returns-arn-and-supported-file-formats"
GROUP = "content"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


_ARN_RE = re.compile(r"^arn:[A-Za-z0-9][-.A-Za-z0-9]{0,62}:pricing:::price-list/[A-Za-z0-9+_/.-]{1,1023}$")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPriceLists returns a well-formed price-list ARN together with the file
    formats that ARN can actually be downloaded in."""
    pricing = _pricing_client(ctx)
    now = datetime.now(timezone.utc)
    resp = pricing.list_price_lists(
        ServiceCode="AmazonEC2",
        EffectiveDate=now,
        CurrencyCode="USD",
        RegionCode="us-east-1",
        MaxResults=5,
    )
    price_lists = resp["PriceLists"]
    assert price_lists
    entry = price_lists[0]
    assert _ARN_RE.match(entry["PriceListArn"]), entry["PriceListArn"]
    assert entry["CurrencyCode"] == "USD"
    assert entry["FileFormats"], "expected at least one downloadable file format"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
