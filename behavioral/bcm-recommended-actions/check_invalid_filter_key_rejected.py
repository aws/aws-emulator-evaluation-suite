"""invalid-filter-key-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-filter-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ActionFilter with a key other than FEATURE, SEVERITY or TYPE fails with ValidationException and
    the exact enum message, while the same request with key FEATURE succeeds."""
    raw = ctx.client("bcm-recommended-actions", config=Config(parameter_validation=False))
    bad_filter = {"actions": [{"key": "NOT_A_REAL_KEY", "matchOption": "EQUALS", "values": ["x"]}]}

    error = _client_error(lambda: raw.list_recommended_actions(filter=bad_filter))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for filter key NOT_A_REAL_KEY, got {error.get('Code')!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'filter.actions.1.member.key' failed to satisfy "
        "constraint: Member must satisfy enum value set: [FEATURE, TYPE, SEVERITY]"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: same shape, a supported key.
    good_filter = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": ["IAM"]}]}
    control = ctx.client("bcm-recommended-actions").list_recommended_actions(filter=good_filter)
    assert "recommendedActions" in control, f"expected recommendedActions in response for supported key FEATURE, got keys {sorted(control)}"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting an
    unsupported filter key fails as itself and not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects filter key NOT_A_REAL_KEY, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

