"""get-price-list-file-url-nonexistent-arn-resource-not-found-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

import botocore.exceptions
from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-price-list-file-url-nonexistent-arn-resource-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )



def _error_code(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A price-list ARN that matches the required pattern but does not correspond to
    any real price list is rejected with NotFoundException, while a real ARN
    obtained from ListPriceLists still resolves successfully."""
    pricing = _pricing_client(ctx)

    fake_arn = "arn:aws:pricing:::price-list/aws/AmazonEC2/USD/99999999999999/us-east-1"
    code, msg = _error_code(lambda: pricing.get_price_list_file_url(PriceListArn=fake_arn, FileFormat="json"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == f"Price list file with arn {fake_arn} and file format json is not found.", msg

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
    assert control["Url"].startswith("https://"), control.get("Url")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
