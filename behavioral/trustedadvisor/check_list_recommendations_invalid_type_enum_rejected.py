"""list-recommendations-invalid-type-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-invalid-type-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["trustedadvisor"]

INVALID_TYPE_MESSAGE = (
    "1 validation error detected: Value 'not_a_real_type' at 'type' failed to satisfy "
    "constraint: Member must satisfy enum value set: [priority, standard]"
)


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


def _outcome(fn):
    """Call fn(); return its error code, or "(accepted)" when it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return "(accepted)"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRecommendations rejects an out-of-enum `type` filter with ValidationException naming
    the enum, while a well-formed single-page call is not refused by that validation."""
    ta = ctx.client("trustedadvisor")

    malformed_code, malformed_msg = _error(lambda: ta.list_recommendations(type="not_a_real_type"))
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for an invalid type enum value, got {malformed_code!r}"
    )
    assert malformed_msg == INVALID_TYPE_MESSAGE, (
        f"expected the exact enum-violation message {INVALID_TYPE_MESSAGE!r}, got {malformed_msg!r}"
    )

    # control: a well-formed call is not refused by the same validation, so the rejection above
    # is not a blanket refusal. The call may succeed or be refused for another reason; neither
    # is graded.
    control_code = _outcome(lambda: ta.list_recommendations(maxResults=100))
    assert control_code != malformed_code, (
        "a well-formed ListRecommendations call must not be rejected like the invalid-enum one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
