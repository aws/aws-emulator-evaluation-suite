"""search-facets-invalid-facet-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-facets-invalid-facet-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchFacets rejects a facetTypes value outside the documented enum with ValidationException."""
    client = ctx.client("marketplace-discovery")

    control = client.search_facets(facetTypes=["CATEGORY"])
    assert "totalResults" in control, f"expected totalResults in control response, got {control!r}"

    error = _error(lambda: client.search_facets(facetTypes=["NOT_A_REAL_FACET_TYPE"]))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r}"
    )
    expected_message = (
        "1 validation error detected: Value '[NOT_A_REAL_FACET_TYPE]' at 'facetTypes' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
        "[FULFILLMENT_OPTION_TYPE, PRICING_MODEL, NUMBER_OF_PRODUCTS, DEPLOYED_ON_AWS, "
        "CERTIFICATES, PUBLISHER, AVERAGE_CUSTOMER_RATING, PRICING_UNIT, CATEGORY]]"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
