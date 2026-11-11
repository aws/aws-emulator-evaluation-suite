"""political-view-invalid-pattern-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "political-view-invalid-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-places"]


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geocode with a lowercase PoliticalView is rejected with ValidationException and its exact message,
    while a valid uppercase code on the same query returns results.
    """
    geo = ctx.client("geo-places")

    code, message = _error_code(lambda: geo.geocode(QueryText="Seattle, WA", PoliticalView="us"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "'PoliticalView' must match regex ^([A-Z]{2}|[A-Z]{3})$"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a well-formed, actually-supported political view code
    # succeeds (not every syntactically valid alpha-3 code is a supported
    # political view -- "RUS" is documented as supported).
    control = geo.geocode(QueryText="Seattle, WA", PoliticalView="RUS", MaxResults=1)
    assert control.get("ResultItems"), "control Geocode call unexpectedly returned no results"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
