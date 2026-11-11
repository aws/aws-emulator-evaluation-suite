"""search-listings-rating-filter-multiple-values-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-rating-filter-multiple-values-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MIN_AVERAGE_CUSTOMER_RATING is a range filter and must carry exactly one value; two values are rejected."""
    client = ctx.client("marketplace-discovery")

    control = client.search_listings(
        filters=[{"filterType": "MIN_AVERAGE_CUSTOMER_RATING", "filterValues": ["1.0"]}],
        maxResults=1,
    )
    assert isinstance(control.get("totalResults"), int) and control["totalResults"] >= 0, (
        f"expected a non-negative totalResults from a single-value rating filter, got {control!r}"
    )

    error = _error(
        lambda: client.search_listings(
            filters=[{"filterType": "MIN_AVERAGE_CUSTOMER_RATING", "filterValues": ["1.0", "2.0"]}],
            maxResults=1,
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for a two-value rating filter, got {error.get('Code')!r}"
    )
    expected_message = "Range filter MIN_AVERAGE_CUSTOMER_RATING requires exactly one value"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
