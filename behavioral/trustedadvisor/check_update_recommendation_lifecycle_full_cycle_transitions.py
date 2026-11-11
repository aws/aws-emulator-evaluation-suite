"""update-recommendation-lifecycle-full-cycle-transitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-recommendation-lifecycle-full-cycle-transitions"
GROUP = "lifecycle-state-machine"
SERVICES = ["trustedadvisor"]


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Without a Trusted Advisor Priority entitlement, UpdateRecommendationLifecycle to in_progress,
    dismissed and pending_response, and GetRecommendation on the same identifier, each fail with
    AccessDeniedException "Access denied due to support level".
    """
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    assert account_id and account_id.isdigit() and len(account_id) == 12, (
        f"positive control failed: STS GetCallerIdentity did not resolve a usable "
        f"account id, got {account_id!r} -- cannot distinguish a support-level denial "
        f"from broken credentials"
    )

    ta = ctx.client("trustedadvisor")
    # Well-formed per UpdateRecommendationLifecycle's own ARN pattern, but naming no
    # recommendation that exists. Entitlement is evaluated before existence, so this
    # exercises the refusal without creating or discovering a real recommendation.
    bogus_arn = f"arn:aws:trustedadvisor::{account_id}:recommendation/deadbeefdeadbeefdeadbeefdeadbeef"

    for stage, reason_code in (
        ("in_progress", "other"),
        ("dismissed", "low_priority"),
        ("pending_response", "other"),
    ):
        error = _error(
            lambda stage=stage, reason_code=reason_code: ta.update_recommendation_lifecycle(
                recommendationIdentifier=bogus_arn,
                lifecycleStage=stage,
                updateReason=f"sim2real behavioral fidelity check: entering {stage}",
                updateReasonCode=reason_code,
            )
        )
        assert error is not None, (
            f"expected UpdateRecommendationLifecycle(lifecycleStage={stage!r}) to be "
            f"refused on an account without Trusted Advisor Priority access, but it "
            f"succeeded"
        )
        assert error["Code"] == "AccessDeniedException", (
            f"expected AccessDeniedException for lifecycleStage={stage!r}, got "
            f"{error['Code']!r} ({error.get('Message')!r})"
        )
        assert error.get("Message") == "Access denied due to support level", (
            f"expected the specific support-level denial message for "
            f"lifecycleStage={stage!r}, got {error.get('Message')!r}"
        )

    # Independent read at a different operation: GetRecommendation on the identical
    # identifier is refused the same way, confirming this is the account's blanket
    # Trusted Advisor Priority entitlement gate and not a quirk of the mutating call.
    read_error = _error(lambda: ta.get_recommendation(recommendationIdentifier=bogus_arn))
    assert read_error is not None, (
        "expected GetRecommendation to be refused on the same identifier, but it succeeded"
    )
    assert read_error["Code"] == "AccessDeniedException", (
        f"expected GetRecommendation to be refused with AccessDeniedException too, got "
        f"{read_error['Code']!r} ({read_error.get('Message')!r})"
    )
    assert read_error.get("Message") == "Access denied due to support level", (
        f"expected the specific support-level denial message from GetRecommendation, "
        f"got {read_error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
