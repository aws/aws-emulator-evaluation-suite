"""get-recommendation-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-recommendation-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["trustedadvisor"]

MALFORMED_ID_MESSAGE = (
    "1 validation error detected: Value 'not-an-arn-at-all-padded-out' at "
    "'recommendationIdentifier' failed to satisfy constraint: Member must satisfy regular "
    "expression pattern: arn:[\\w-]+:trustedadvisor::\\d{12}:recommendation\\/[\\w-]+"
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
    """A syntactically malformed recommendationIdentifier is rejected with ValidationException
    naming the ARN pattern, while a well-formed identifier is not refused by that validation."""
    ta = ctx.client("trustedadvisor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # break exactly one thing: violate the ARN pattern entirely (but keep it >= the
    # AccountRecommendationIdentifier's client-side min length of 20 chars, so the
    # request actually reaches the service instead of failing local param validation)
    malformed_code, malformed_msg = _error(
        lambda: ta.get_recommendation(recommendationIdentifier="not-an-arn-at-all-padded-out")
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a malformed ARN, got {malformed_code!r}"
    )
    assert malformed_msg == MALFORMED_ID_MESSAGE, (
        f"expected the exact pattern-violation message {MALFORMED_ID_MESSAGE!r}, got {malformed_msg!r}"
    )

    # control: a well-formed identifier is not refused by the same validation, so the rejection
    # above is not a blanket refusal. It names no recommendation, so it may be refused for
    # another reason; which one is not graded.
    well_formed_missing_arn = (
        f"arn:aws:trustedadvisor::{account_id}:recommendation/00000000-0000-0000-0000-000000000000"
    )
    control_code = _outcome(
        lambda: ta.get_recommendation(recommendationIdentifier=well_formed_missing_arn)
    )
    assert control_code != malformed_code, (
        "a well-formed identifier must not be rejected like the malformed one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
