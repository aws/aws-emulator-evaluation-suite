"""get-listing-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetListing on a well-formed but non-existent listingId is rejected; a real listing still resolves."""
    client = ctx.client("marketplace-discovery")

    bogus_id = "sim2real-nonexistent-listing-" + "0" * 32
    error = _error(lambda: client.get_listing(listingId=bogus_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent listingId, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Listing not found", (
        f"expected message 'Listing not found', got {error.get('Message')!r}"
    )

    # Positive control: a real listing discovered via search still resolves.
    search_resp = client.search_listings(maxResults=1)
    assert search_resp["listingSummaries"], "need a real listing for the positive control"
    real_id = search_resp["listingSummaries"][0]["listingId"]
    detail = client.get_listing(listingId=real_id)
    assert detail["listingId"] == real_id, (
        f"expected GetListing({real_id!r}) to resolve, got listingId={detail.get('listingId')!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects GetListing on a nonexistent listingId, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
