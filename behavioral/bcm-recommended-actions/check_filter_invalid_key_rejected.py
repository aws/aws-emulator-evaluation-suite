"""filter-invalid-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-invalid-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


def _error_response(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ActionFilter.key outside {FEATURE, SEVERITY, TYPE} is rejected with ValidationException, not silently ignored."""
    client = ctx.client("bcm-recommended-actions")

    bad_filter = {"actions": [{"key": "BOGUS_KEY", "matchOption": "EQUALS", "values": ["x"]}]}
    error = _error_response(lambda: client.list_recommended_actions(filter=bad_filter))

    assert error is not None, "expected ListRecommendedActions to reject an unsupported filter key"
    assert error["Error"]["Code"] == "ValidationException", (
        f"expected ValidationException, got {error['Error']['Code']}: {error['Error'].get('Message')}"
    )
    expected_message = (
        "1 validation error detected: Value at 'filter.actions.1.member.key' failed to satisfy "
        "constraint: Member must satisfy enum value set: [FEATURE, TYPE, SEVERITY]"
    )
    assert error["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error['Error'].get('Message')!r}"
    )
    assert error.get("reason") == "fieldValidationFailed", (
        f"expected reason=fieldValidationFailed for an out-of-enum filter key, got {error.get('reason')!r}"
    )
    field_names = [f.get("name") for f in error.get("fieldList", [])]
    assert any("key" in name for name in field_names if name), (
        f"expected fieldList to name the offending key field, got {field_names!r}"
    )

    # Positive control: an otherwise-identical request using a supported key succeeds.
    good_filter = {"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["CRITICAL"]}]}
    control = client.list_recommended_actions(filter=good_filter)
    assert isinstance(control["recommendedActions"], list)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
