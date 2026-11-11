"""filter-invalid-match-option-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-invalid-match-option-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]

# The specific ValidationExceptionReason AWS returns for an out-of-domain
# ActionFilter.matchOption, not the full
# modeled enum (unknownOperation | cannotParse | fieldValidationFailed | other),
# which would accept any ValidationException regardless of cause.
_EXPECTED_REASON = "fieldValidationFailed"


def _error_response(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ActionFilter.matchOption outside {EQUALS, NOT_EQUALS} is rejected with ValidationException."""
    client = ctx.client("bcm-recommended-actions")

    bad_filter = {"actions": [{"key": "SEVERITY", "matchOption": "CONTAINS", "values": ["CRITICAL"]}]}
    error = _error_response(lambda: client.list_recommended_actions(filter=bad_filter))

    assert error is not None, "expected ListRecommendedActions to reject an unsupported matchOption"
    assert error["Error"]["Code"] == "ValidationException", f"expected ValidationException, got {error['Error']['Code']}"
    expected_message = (
        "1 validation error detected: Value at 'filter.actions.1.member.matchOption' failed to "
        "satisfy constraint: Member must satisfy enum value set: [NOT_EQUALS, EQUALS]"
    )
    assert error["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error['Error'].get('Message')!r}"
    )
    assert error["reason"] == _EXPECTED_REASON, f"expected reason={_EXPECTED_REASON!r}, got {error['reason']!r}"

    # Positive control: an otherwise-identical request using a supported matchOption succeeds.
    good_filter = {"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["CRITICAL"]}]}
    control = client.list_recommended_actions(filter=good_filter)
    assert isinstance(control["recommendedActions"], list), f"expected a list, got {type(control['recommendedActions'])!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
