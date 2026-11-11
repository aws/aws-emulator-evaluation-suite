"""max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """maxResults 0 and 1001 each fail with ValidationException and the exact range message, while a
    value inside [1, 1000] succeeds."""
    # Client-side parameter validation would otherwise short-circuit this before it ever
    # reaches the wire (maxResults carries the same min:1/max:1000 range constraint in the
    # model), so use a client with validation disabled to exercise the server-side rejection.
    raw = ctx.client("bcm-recommended-actions", config=Config(parameter_validation=False))

    error_low = _client_error(lambda: raw.list_recommended_actions(maxResults=0))
    assert error_low.get("Code") == "ValidationException", (
        f"maxResults=0 (below the documented minimum of 1) got error code "
        f"{error_low.get('Code')!r}, expected 'ValidationException'"
    )
    expected_low = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert error_low.get("Message") == expected_low, (
        f"maxResults=0: expected message {expected_low!r}, got {error_low.get('Message')!r}"
    )

    error_high = _client_error(lambda: raw.list_recommended_actions(maxResults=1001))
    assert error_high.get("Code") == "ValidationException", (
        f"maxResults=1001 (above the documented maximum of 1000) got error code "
        f"{error_high.get('Code')!r}, expected 'ValidationException'"
    )
    expected_high = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert error_high.get("Message") == expected_high, (
        f"maxResults=1001: expected message {expected_high!r}, got {error_high.get('Message')!r}"
    )

    # Positive control: a value inside the documented range still succeeds.
    control = ctx.client("bcm-recommended-actions").list_recommended_actions(maxResults=5)
    assert "recommendedActions" in control, (
        f"a documented in-range maxResults=5 did not return 'recommendedActions': {control!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting an
    out-of-range maxResults fails as itself and not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this maxResults value, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
