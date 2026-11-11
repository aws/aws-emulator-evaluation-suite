"""search-listings-rating-filter-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-rating-filter-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A MIN_AVERAGE_CUSTOMER_RATING filter value above 5.0 is rejected; 5.0 itself and 4.0 still succeed."""
    client = ctx.client("marketplace-discovery")

    bad_filters = [{"filterType": "MIN_AVERAGE_CUSTOMER_RATING", "filterValues": ["6.0"]}]
    error = _error(lambda: client.search_listings(filters=bad_filters))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for rating 6.0, got {error.get('Code')!r}"
    )
    expected_message = (
        "Range filter MIN_AVERAGE_CUSTOMER_RATING value must be between 0.0 and 5.0, got: 6.0"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: the documented maximum (5.0) and an in-range value (4.0) both succeed.
    for good_value in ("4.0", "5.0"):
        good_filters = [{"filterType": "MIN_AVERAGE_CUSTOMER_RATING", "filterValues": [good_value]}]
        resp = client.search_listings(filters=good_filters)
        assert isinstance(resp["totalResults"], int) and resp["totalResults"] >= 0, (
            f"expected a non-negative int totalResults for rating filter {good_value}, "
            f"got {resp.get('totalResults')!r}"
        )


def _error(fn):
    """Call fn(); return its Error dict. An unexpected SUCCESS raises, because an emulator accepting
    input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
