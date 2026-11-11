"""invalid-match-option-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-match-option-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ActionFilter with a matchOption other than EQUALS or NOT_EQUALS fails with ValidationException
    and the exact enum message, while the same request with a supported matchOption succeeds."""
    # Parameter validation disabled so an out-of-enum matchOption reaches the server and is
    # not caught locally by botocore.
    unvalidated = ctx.client("bcm-recommended-actions", config=Config(parameter_validation=False))
    bad_filter = {"actions": [{"key": "FEATURE", "matchOption": "CONTAINS", "values": ["IAM"]}]}

    error = _client_error(lambda: unvalidated.list_recommended_actions(filter=bad_filter))
    assert error.get("Code") == "ValidationException", f"unexpected error code: {error.get('Code')!r}"
    expected_message = (
        "1 validation error detected: Value at 'filter.actions.1.member.matchOption' failed to "
        "satisfy constraint: Member must satisfy enum value set: [NOT_EQUALS, EQUALS]"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: same shape, a supported matchOption.
    good_filter = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": ["IAM"]}]}
    control = ctx.client("bcm-recommended-actions").list_recommended_actions(filter=good_filter)
    assert isinstance(control["recommendedActions"], list), (
        f"expected a list, got {control.get('recommendedActions')!r}"
    )


def _client_error(fn) -> dict:
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("expected ListRecommendedActions to reject an unsupported matchOption")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
