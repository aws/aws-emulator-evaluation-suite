"""list-price-lists-malformed-currency-pattern-invalid-parameter-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

import botocore.exceptions
from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-price-lists-malformed-currency-pattern-invalid-parameter-rejected"
GROUP = "overly-permissive"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a malformed CurrencyCode real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call with InvalidParameterException, but it SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPriceLists rejects a CurrencyCode that violates the ^[A-Z]{3}$ pattern with
    InvalidParameterException, while a well-formed currency code still succeeds."""
    pricing = _pricing_client(ctx)
    now = datetime.now(timezone.utc)

    code, msg = _error_code(
        lambda: pricing.list_price_lists(ServiceCode="AmazonEC2", EffectiveDate=now, CurrencyCode="US")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert msg == (
        "1 validation error detected: Value 'US' at 'currencyCode' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [A-Z]{3}"
    ), msg

    control = pricing.list_price_lists(
        ServiceCode="AmazonEC2", EffectiveDate=now, CurrencyCode="USD", MaxResults=1
    )
    assert control["PriceLists"], (
        f"expected a non-empty PriceLists for the well-formed control call, got {control['PriceLists']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
