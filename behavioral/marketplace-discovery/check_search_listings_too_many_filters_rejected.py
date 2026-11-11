"""search-listings-too-many-filters-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-too-many-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SearchListings accepts a request using each discovered filterType once, but fails ValidationException
    'Duplicate filter types: [<type>]' when one filterType appears in two entries."""
    md = ctx.client("marketplace-discovery")

    # Discover one real, catalog-valid filterValue per term facetType via SearchFacets, rather than
    # guessing enum/ID formats — SearchListings' filterValues must match the internal `value` field
    # SearchFacets returns (e.g. PUBLISHER/FULFILLMENT_OPTION_TYPE use internal IDs, not free text).
    term_facet_types = [
        "CATEGORY",
        "PUBLISHER",
        "FULFILLMENT_OPTION_TYPE",
        "PRICING_MODEL",
        "PRICING_UNIT",
        "DEPLOYED_ON_AWS",
        "NUMBER_OF_PRODUCTS",
    ]
    facets_resp = md.search_facets(facetTypes=term_facet_types)
    listing_facets = facets_resp["listingFacets"]

    distinct_filters = [
        {"filterType": "MIN_AVERAGE_CUSTOMER_RATING", "filterValues": ["1.0"]},
        {"filterType": "MAX_AVERAGE_CUSTOMER_RATING", "filterValues": ["5.0"]},
    ]
    first_type, first_value, second_value = None, None, None
    for ftype in term_facet_types:
        values = listing_facets.get(ftype) or []
        if not values:
            continue
        value = values[0]["value"]
        distinct_filters.append({"filterType": ftype, "filterValues": [value]})
        if first_type is None:
            first_type, first_value = ftype, value
            if len(values) >= 2:
                second_value = values[1]["value"]
    assert first_type is not None, "expected at least one populated term facetType in the catalog"

    # positive control: every distinct filterType used at most once is accepted.
    control = md.search_listings(filters=distinct_filters)
    summaries = control["listingSummaries"]
    assert len(summaries) <= control["totalResults"], (
        f"listingSummaries length {len(summaries)} exceeds totalResults {control['totalResults']}"
    )

    # negative: repeating a filterType is rejected even when the two entries carry DIFFERENT real
    # values — it's the repeated filterType key that's disallowed, not merely a literal duplicate
    # entry, and even though the overall entry count (2) is nowhere near the documented 30-entry
    # cap. OR-combination across values belongs inside one entry's filterValues list, never by
    # repeating the entry. Falls back to the same value twice only if the catalog has just one.
    duplicated = [
        {"filterType": first_type, "filterValues": [first_value]},
        {"filterType": first_type, "filterValues": [second_value or first_value]},
    ]
    error = _error(lambda: md.search_listings(filters=duplicated))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for a repeated filterType {first_type!r}, "
        f"got {error.get('Code')!r}"
    )
    expected_message = f"Duplicate filter types: [{first_type}]"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
