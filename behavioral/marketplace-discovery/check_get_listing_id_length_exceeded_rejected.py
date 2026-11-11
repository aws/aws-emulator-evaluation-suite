"""get-listing-id-length-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-listing-id-length-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A listingId of otherwise-valid characters exceeding the 255-char max length is rejected."""
    client = ctx.client("marketplace-discovery")

    too_long_id = "a" * 256
    error = _error(lambda: client.get_listing(listingId=too_long_id))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for a 256-char listingId, got {error.get('Code')!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{too_long_id}' at 'listingId' failed to satisfy "
        f"constraint: Member must have length less than or equal to 255"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: a well-formed, real listingId still resolves.
    search_resp = client.search_listings(maxResults=1)
    assert search_resp["listingSummaries"], "need a real listing for the positive control"
    real_id = search_resp["listingSummaries"][0]["listingId"]
    detail = client.get_listing(listingId=real_id)
    assert detail["listingId"] == real_id, f"expected positive control to resolve {real_id!r}, got {detail.get('listingId')!r}"


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
