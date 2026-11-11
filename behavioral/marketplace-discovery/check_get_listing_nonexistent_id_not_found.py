"""get-listing-nonexistent-id-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-nonexistent-id-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-discovery"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, got a successful response: {resp!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed but nonexistent listingId is rejected with ResourceNotFoundException, while a real one succeeds."""
    client = ctx.client("marketplace-discovery")

    resp = client.search_listings(maxResults=1)
    summaries = resp.get("listingSummaries", [])
    if not summaries:
        raise AssertionError("no listings visible to this account to use as a positive control")
    valid_id = summaries[0]["listingId"]

    control = client.get_listing(listingId=valid_id)
    assert control["listingId"] == valid_id, (
        f"expected positive control GetListing to echo listingId={valid_id!r}, "
        f"got {control.get('listingId')!r}"
    )

    bogus_id = ctx.unique_name("sim2real-nonexistent-listing-")
    error = _error(lambda: client.get_listing(listingId=bogus_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected GetListing on nonexistent listingId={bogus_id!r} to raise "
        f"ResourceNotFoundException, got error code {error.get('Code')!r}"
    )
    assert error.get("Message") == "Listing not found", (
        f"expected message 'Listing not found', got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
