"""search-listings-max-results-exceeds-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-max-results-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchListings rejects maxResults above the documented 1-100 range with ValidationException,
    while maxResults at the boundary (100) is still accepted."""
    md = ctx.client("marketplace-discovery")

    error = _error(lambda: md.search_listings(maxResults=101))
    assert error.get("Code") == "ValidationException", error
    expected_message = (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # positive control, same file: the boundary value itself is accepted.
    control = md.search_listings(maxResults=100)
    assert len(control["listingSummaries"]) <= 100, len(control["listingSummaries"])
    assert control["totalResults"] >= len(control["listingSummaries"]), (
        control["totalResults"],
        len(control["listingSummaries"]),
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
