"""update-recommendation-lifecycle-concurrent-idempotent-writes."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-recommendation-lifecycle-concurrent-idempotent-writes"
GROUP = "concurrency"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"
MALFORMED_ID_MESSAGE = (
    "1 validation error detected: Value 'not-an-arn-at-all-padded-out' at "
    "'recommendationIdentifier' failed to satisfy constraint: Member must satisfy regular "
    "expression pattern: arn:[\\w-]+:trustedadvisor::\\d{12}:recommendation\\/[\\w-]+"
)


def _find_priority_recommendation(ctx):
    ta = ctx.client("trustedadvisor")
    recs = ta.list_recommendations(type="priority", maxResults=10).get(
        "recommendationSummaries", []
    )
    return recs[0]["arn"] if recs else None


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


def _assert_entitlement_gate_is_idempotent_under_concurrency(ctx, ta, gate_message):
    """Without a Trusted Advisor Priority entitlement, concurrent identical
    UpdateRecommendationLifecycle racers must all converge on the same support-level denial,
    never a mix of AccessDenied/Throttling/5xx that would show a nondeterministic gate.
    """
    assert gate_message == SUPPORT_LEVEL_DENIAL, (
        f"expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, got {gate_message!r}"
    )

    # Positive control, same operation: a syntactically malformed identifier must fail local/service
    # validation BEFORE it ever reaches the authorization layer -- proving creds, region and wiring
    # are otherwise healthy and separating "malformed" from "not entitled".
    malformed_code, malformed_msg = _error(
        lambda: ta.update_recommendation_lifecycle(
            recommendationIdentifier="not-an-arn-at-all-padded-out",
            lifecycleStage="in_progress",
            updateReason="sim2real validation-before-authorization probe",
            updateReasonCode="other",
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a malformed identifier, got {malformed_code!r}"
    )
    assert malformed_msg == MALFORMED_ID_MESSAGE, (
        f"expected the exact pattern-violation message {MALFORMED_ID_MESSAGE!r}, got {malformed_msg!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    well_formed_unreachable = (
        f"arn:aws:trustedadvisor::{account_id}:"
        "recommendation/00000000-0000-0000-0000-000000000000"
    )

    def _update():
        ta.update_recommendation_lifecycle(
            recommendationIdentifier=well_formed_unreachable,
            lifecycleStage="in_progress",
            updateReason="sim2real concurrent idempotent lifecycle update test",
            updateReasonCode="other",
        )

    codes = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_update) for _ in range(5)]
        for fut in as_completed(futures):
            try:
                fut.result()
            except ClientError as err:
                codes.append((err.response["Error"]["Code"], err.response["Error"].get("Message")))
            else:
                codes.append(("succeeded", None))

    assert codes == [("AccessDeniedException", SUPPORT_LEVEL_DENIAL)] * 5, (
        f"expected all 5 concurrent racers to converge on the identical support-plan "
        f"denial, got {codes}"
    )
    assert malformed_code != codes[0][0], (
        "a well-formed-but-unreachable identifier must not collapse to the same code "
        "as a malformed one -- that would mean validation is skipped, not enforced"
    )

    # Terminal assertion is an INDEPENDENT read (GetRecommendation, not
    # UpdateRecommendationLifecycle) confirming the effect is absent: the same gate,
    # not just the same call, blocks a different operation on the identical identifier.
    read_code, read_msg = _error(
        lambda: ta.get_recommendation(recommendationIdentifier=well_formed_unreachable)
    )
    assert read_code == "AccessDeniedException", (
        f"expected the independent read (GetRecommendation) to hit the identical "
        f"support-plan gate, got {read_code!r}"
    )
    assert read_msg == SUPPORT_LEVEL_DENIAL, (
        f"expected GetRecommendation's denial message {SUPPORT_LEVEL_DENIAL!r}, got {read_msg!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent identical UpdateRecommendationLifecycle calls all succeed and converge on
    in_progress; without a Trusted Advisor Priority entitlement, all five fail with the same
    AccessDeniedException "Access denied due to support level", and so does GetRecommendation."""
    ta = ctx.client("trustedadvisor")
    try:
        rec_arn = _find_priority_recommendation(ctx)
    except ClientError as err:
        if err.response["Error"]["Code"] != "AccessDeniedException":
            raise
        _assert_entitlement_gate_is_idempotent_under_concurrency(
            ctx, ta, err.response["Error"].get("Message", "")
        )
        return
    if rec_arn is None:
        raise AssertionError(
            "account has no priority (type=priority) recommendations to exercise "
            "concurrent lifecycle updates against"
        )

    def _update():
        # UpdateRecommendationLifecycle is documented idempotent; N racers setting
        # the SAME target stage on the SAME recommendation must all succeed.
        ta.update_recommendation_lifecycle(
            recommendationIdentifier=rec_arn,
            lifecycleStage="in_progress",
            updateReason="sim2real concurrent idempotent lifecycle update test",
            updateReasonCode="other",
        )

    errors = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_update) for _ in range(5)]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:  # noqa: BLE001 - collecting for the assertion below
                errors.append(exc)

    assert not errors, f"idempotent concurrent lifecycle updates raised: {errors}"

    deadline = time.monotonic() + 20.0
    stage = None
    while time.monotonic() < deadline:
        stage = ta.get_recommendation(recommendationIdentifier=rec_arn)["recommendation"].get(
            "lifecycleStage"
        )
        if stage == "in_progress":
            break
        time.sleep(2.0)
    assert stage == "in_progress", f"expected converged lifecycleStage=in_progress, got {stage!r}"

    # leave the recommendation in a re-usable resting state
    ta.update_recommendation_lifecycle(
        recommendationIdentifier=rec_arn,
        lifecycleStage="pending_response",
        updateReason="sim2real behavioral fidelity check: resetting to pending_response",
        updateReasonCode="other",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
