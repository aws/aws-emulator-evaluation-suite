"""get-listing-not-found-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-listing-not-found-error"
GROUP = "error-semantics"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetListing for a well-formed but nonexistent listingId raises ResourceNotFoundException,
    while a real listing discovered via search still resolves (positive control)."""
    md = ctx.client("marketplace-discovery")

    search_resp = md.search_listings(maxResults=1)
    summaries = search_resp.get("listingSummaries", [])
    assert summaries, "no listings visible to this account to use as a positive control"
    real_id = summaries[0]["listingId"]
    control = md.get_listing(listingId=real_id)
    assert control["listingId"] == real_id, (
        f"positive control failed: expected listingId={real_id!r}, got {control.get('listingId')!r}"
    )

    bogus_id = ctx.unique_name("sim2real-behav-nonexistent-listing-")
    error = _error(lambda: md.get_listing(listingId=bogus_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')}"
    )
    assert error.get("Message") == "Listing not found", (
        f"expected message 'Listing not found', got {error.get('Message')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
