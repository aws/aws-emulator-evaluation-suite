"""search-listings-searchtext-too-long-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "search-listings-searchtext-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SearchListings rejects a searchText longer than the documented 512-character maximum, while
    a searchText at the boundary (exactly 512 characters) is still accepted."""
    client = ctx.client("marketplace-discovery")

    # positive control, general: an ordinary searchText succeeds.
    control = client.search_listings(searchText="cloud infrastructure", maxResults=1)
    assert "totalResults" in control, f"expected totalResults in response, got keys {sorted(control)}"

    # positive control, boundary: exactly 512 characters is still within the documented maximum.
    boundary = client.search_listings(searchText="x" * 512, maxResults=1)
    assert "totalResults" in boundary, f"expected totalResults in response, got keys {sorted(boundary)}"

    too_long = "x" * 513
    error = _error(lambda: client.search_listings(searchText=too_long, maxResults=1))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{too_long}' at 'searchText' failed to satisfy "
        f"constraint: Member must have length less than or equal to 512"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
