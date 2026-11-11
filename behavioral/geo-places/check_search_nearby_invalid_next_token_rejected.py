"""search-nearby-invalid-next-token-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "search-nearby-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-places"]


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A syntactically bogus NextToken is rejected rather than silently treated as fresh.

    A faithful backend must reject the malformed cursor with ValidationException and
    return no results, while the same query without a NextToken succeeds normally.
    """
    geo = ctx.client("geo-places")
    position = [-122.3493, 47.6205]

    code, message = _error_code(
        lambda: geo.search_nearby(QueryPosition=position, NextToken="not-a-real-next-token")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "'NextToken' must be a valid token."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the same query without a NextToken succeeds.
    control = geo.search_nearby(QueryPosition=position, MaxResults=5)
    assert control.get("ResultItems"), "control SearchNearby call unexpectedly returned no results"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
