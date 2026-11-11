"""list-price-lists-unsupported-currency-resource-not-found-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

import botocore.exceptions
from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-price-lists-unsupported-currency-resource-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a currency real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects CurrencyCode=ZZZ, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPriceLists with a currency no price list is published in fails with
    AccessDeniedException ("Caller is not authorized to access requested price lists"), while
    USD for the same service and date succeeds."""
    pricing = _pricing_client(ctx)
    now = datetime.now(timezone.utc)

    code, msg = _error_code(
        lambda: pricing.list_price_lists(ServiceCode="AmazonEC2", EffectiveDate=now, CurrencyCode="ZZZ")
    )
    assert code == "AccessDeniedException", (code, msg)
    assert msg == "Caller is not authorized to access requested price lists", msg

    control = pricing.list_price_lists(
        ServiceCode="AmazonEC2", EffectiveDate=now, CurrencyCode="USD", MaxResults=1
    )
    assert control["PriceLists"], f"expected at least one USD price list, got {control!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
