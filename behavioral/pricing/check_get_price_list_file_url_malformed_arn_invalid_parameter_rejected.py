"""get-price-list-file-url-malformed-arn-invalid-parameter-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

import botocore.exceptions
from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-price-list-file-url-malformed-arn-invalid-parameter-rejected"
GROUP = "overly-permissive"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _error_code(fn):
    """An unexpected SUCCESS raises rather than returning a falsy sentinel."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPriceListFileUrl rejects an ARN that violates the pricing price-list ARN
    pattern (right length, wrong shape) with InvalidParameterException, while a real
    price-list ARN obtained from ListPriceLists still succeeds."""
    pricing = _pricing_client(ctx)

    bad_arn = "arn:aws:pricing:::not-a-price-list/AmazonEC2/some-fake-id"
    code, msg = _error_code(lambda: pricing.get_price_list_file_url(PriceListArn=bad_arn, FileFormat="json"))
    assert code == "InvalidParameterException", (code, msg)
    assert msg == (
        f"1 validation error detected: Value '{bad_arn}' at 'priceListArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "arn:[A-Za-z0-9][-.A-Za-z0-9]{0,62}:pricing:::price-list/[A-Za-z0-9+_/.-]{1,1023}"
    ), msg

    now = datetime.now(timezone.utc)
    listing = pricing.list_price_lists(
        ServiceCode="AmazonEC2",
        EffectiveDate=now,
        CurrencyCode="USD",
        RegionCode="us-east-1",
        MaxResults=1,
    )
    entry = listing["PriceLists"][0]
    control = pricing.get_price_list_file_url(
        PriceListArn=entry["PriceListArn"], FileFormat=entry["FileFormats"][0]
    )
    assert control["Url"].startswith("https://"), (
        f"expected an https price-list URL for a real ARN, got {control['Url']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
