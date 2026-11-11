"""getplace-unresolvable-place-id-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "getplace-unresolvable-place-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-places"]


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetPlace on a plausible but unresolvable PlaceId is rejected with ValidationException and its exact
    message, while a PlaceId from Geocode resolves to a place with a Title.
    """
    geo = ctx.client("geo-places")

    bogus_place_id = "this-place-id-does-not-exist-1234567890abcdef"
    code, message = _error_code(lambda: geo.get_place(PlaceId=bogus_place_id))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "'PlaceId' must be a valid ID."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a real PlaceId, freshly minted by Geocode, resolves.
    geocoded = geo.geocode(QueryText="Seattle, WA, USA", MaxResults=1)
    items = geocoded.get("ResultItems", [])
    assert items, "expected a geocode result to seed the positive control"
    control = geo.get_place(PlaceId=items[0]["PlaceId"])
    assert control.get("Title"), "control GetPlace call unexpectedly returned no Title"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
