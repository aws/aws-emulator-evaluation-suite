"""geocode-missing-query-input-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "geocode-missing-query-input-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-places"]


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected Geocode to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geocode requires either QueryText or QueryComponents; omitting both is rejected.

    A faithful backend must reject the call with ValidationException and return no
    results, while a normal Geocode call with QueryText still succeeds.
    """
    geo = ctx.client("geo-places")

    code, message = _error_code(lambda: geo.geocode())
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "At least one of the following fields must be set: 'QueryText', 'QueryComponents'."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a well-formed call still succeeds and returns results.
    control = geo.geocode(QueryText="Seattle, WA, USA", MaxResults=1)
    assert control.get("ResultItems"), "control Geocode call unexpectedly returned no results"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
