"""update-recommendation-lifecycle-short-reason-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-recommendation-lifecycle-short-reason-rejected"
GROUP = "overly-permissive"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"
SHORT_REASON_MESSAGE = (
    "1 validation error detected: Value at 'updateReason' failed to satisfy constraint: "
    "Member must have length greater than or equal to 10"
)


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRecommendationLifecycle with an updateReason under 10 characters fails with
    ValidationException and the exact length message, while the same call with a valid-length reason
    fails with AccessDeniedException "Access denied due to support level": length is checked first.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    # Well-formed by AccountRecommendationIdentifier's ^arn:...:recommendation/[\w-]+$ pattern, but
    # not a real recommendation -- without a Priority entitlement none can be listed or created,
    # so the ARN's existence is not the thing under test, only its syntax.
    fake_arn = f"arn:aws:trustedadvisor::{account}:recommendation/00000000-0000-0000-0000-000000000000"
    raw = ctx.client("trustedadvisor", config=Config(parameter_validation=False))

    # break exactly one thing: updateReason below the documented 10-char minimum
    bad_code, bad_msg = _error(
        lambda: raw.update_recommendation_lifecycle(
            recommendationIdentifier=fake_arn,
            lifecycleStage="dismissed",
            updateReason="short",
            updateReasonCode="other",
        )
    )
    assert bad_code == "ValidationException", (
        f"expected a server-side ValidationException for a too-short updateReason, got {bad_code!r}"
    )
    assert bad_msg == SHORT_REASON_MESSAGE, (
        f"expected the exact length-violation message {SHORT_REASON_MESSAGE!r}, got {bad_msg!r}"
    )

    # positive control, same operation and same (fake) identifier: only the reason's length
    # differs. A valid-length reason clears the field validation just enforced above and is denied
    # instead by the account's own Priority entitlement gate -- proving the two codes are not the
    # same "everything is denied" answer wearing different names.
    control_code, control_msg = _error(
        lambda: raw.update_recommendation_lifecycle(
            recommendationIdentifier=fake_arn,
            lifecycleStage="dismissed",
            updateReason="a properly long update reason for this fidelity check",
            updateReasonCode="other",
        )
    )
    assert control_code == "AccessDeniedException", (
        f"expected AccessDeniedException (support-plan gate) once the reason clears the length "
        f"check, got {control_code!r}"
    )
    assert control_msg == SUPPORT_LEVEL_DENIAL, (
        f"expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, got {control_msg!r}"
    )
    assert control_code != bad_code, (
        "a too-short updateReason and a valid-length one must not collapse to the same error code"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
