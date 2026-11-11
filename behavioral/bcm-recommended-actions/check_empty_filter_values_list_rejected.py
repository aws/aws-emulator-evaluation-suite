"""empty-filter-values-list-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-filter-values-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ActionFilter with an empty values list fails with ValidationException and the exact length
    message, while the same filter with one value succeeds: values has a minimum length of 1."""
    unvalidated = ctx.client("bcm-recommended-actions", config=Config(parameter_validation=False))
    bad_filter = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": []}]}

    error = _client_error(lambda: unvalidated.list_recommended_actions(filter=bad_filter))
    assert error.get("Code") == "ValidationException", (
        f"an empty ActionFilter.values list was not rejected with ValidationException, got {error.get('Code')!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'filter.actions.1.member.values' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: same shape, a non-empty values list.
    good_filter = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": ["IAM"]}]}
    control = ctx.client("bcm-recommended-actions").list_recommended_actions(filter=good_filter)
    assert "recommendedActions" in control, (
        f"the positive control (non-empty values list) did not return recommendedActions: {control!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting an
    empty values list fails as itself and not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects an empty ActionFilter.values list, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
