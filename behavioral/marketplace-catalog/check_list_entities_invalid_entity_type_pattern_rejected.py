"""list-entities-invalid-entity-type-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-entities-invalid-entity-type-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEntities refuses an EntityType containing a digit with ValidationException, the same code as a
    letters-only unknown type, each with its exact message; a real EntityType returns a list.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    code, msg = _error_code(lambda: mp.list_entities(Catalog="AWSMarketplace", EntityType="Ami1Product"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == "[Requested entity type 'Ami1Product' is invalid.]", msg

    # contrast: a letters-only value that satisfies the pattern but names no real
    # product type gets the SAME ValidationException, not a distinct not-found code.
    contrast_code, contrast_msg = _error_code(
        lambda: mp.list_entities(Catalog="AWSMarketplace", EntityType="NotARealMarketplaceProductType")
    )
    assert contrast_code == "ValidationException", (
        f"expected ValidationException for a letters-only unsupported type, got {contrast_code}"
    )
    assert contrast_msg == "[Requested entity type 'NotARealMarketplaceProductType' is invalid.]", contrast_msg

    # positive control: a well-formed, real product type succeeds outright.
    resp = mp.list_entities(Catalog="AWSMarketplace", EntityType="AmiProduct", MaxResults=1)
    assert "EntitySummaryList" in resp


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
