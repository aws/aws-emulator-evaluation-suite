"""filter-match-option-wrong-case-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-match-option-wrong-case-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A matchOption of lowercase "equals" fails with ValidationException and the exact enum message,
    while the same filter with "EQUALS" succeeds: matchOption is case-sensitive."""
    client = ctx.client("bcm-recommended-actions")

    error = _client_error(
        lambda: client.list_recommended_actions(
            filter={"actions": [{"key": "SEVERITY", "matchOption": "equals", "values": ["CRITICAL"]}]}
        )
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')!r}"
    expected_message = (
        "1 validation error detected: Value at 'filter.actions.1.member.matchOption' failed to "
        "satisfy constraint: Member must satisfy enum value set: [NOT_EQUALS, EQUALS]"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: identical filter, correctly-cased matchOption -> succeeds.
    control = client.list_recommended_actions(
        filter={"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["CRITICAL"]}]}
    )
    assert isinstance(control["recommendedActions"], list), (
        f"expected recommendedActions to be a list, got {control.get('recommendedActions')!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict. An unexpected success raises, so accepting a
    lowercase matchOption fails as itself and not as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects matchOption='equals' (wrong case), but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
