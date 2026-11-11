"""get-listing-invalid-id-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-invalid-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A listingId that violates the ^[\\w\\-]+$ pattern is rejected with ValidationException, not silently accepted."""
    client = ctx.client("marketplace-discovery")

    resp = client.search_listings(maxResults=1)
    summaries = resp.get("listingSummaries", [])
    if not summaries:
        raise AssertionError("no listings visible to this account to use as a positive control")
    valid_id = summaries[0]["listingId"]

    control = client.get_listing(listingId=valid_id)
    assert control["listingId"] == valid_id, (
        f"positive control: expected GetListing({valid_id!r}) to echo listingId "
        f"{valid_id!r}, got {control.get('listingId')!r}"
    )

    error = _error(lambda: client.get_listing(listingId="not a valid id! (has spaces & punctuation)"))
    assert error.get("Code") == "ValidationException", (
        f"expected a listingId violating ^[\\w-]+$ to be rejected with "
        f"'ValidationException', got {error.get('Code')!r}"
    )
    # AWS echoes the value with its '&' entity-escaped twice.
    expected_message = (
        "1 validation error detected: Value 'not a valid id! (has spaces &amp;amp; punctuation)' "
        "at 'listingId' failed to satisfy constraint: Member must satisfy regular expression "
        "pattern: [\\w\\-]+"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
