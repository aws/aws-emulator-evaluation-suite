"""get-recommendation-matches-list-summary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-recommendation-matches-list-summary"
GROUP = "error-semantics"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"
MALFORMED_ID_MESSAGE = (
    "1 validation error detected: Value 'not-an-arn-at-all-padded-out' at "
    "'recommendationIdentifier' failed to satisfy constraint: Member must satisfy regular "
    "expression pattern: arn:[\\w-]+:trustedadvisor::\\d{12}:recommendation\\/[\\w-]+"
)


def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response
    raise AssertionError("expected a ClientError, got a success response")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Without a support-level entitlement, ListRecommendations and GetRecommendation both fail with
    AccessDeniedException (HTTP 403) "Access denied due to support level", while a malformed
    identifier fails GetRecommendation with ValidationException and the exact message.
    """
    ta = ctx.client("trustedadvisor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    list_code, list_resp = _error_code(lambda: ta.list_recommendations(maxResults=1))
    assert list_code == "AccessDeniedException", (
        f"expected AccessDeniedException (support-plan gate) for ListRecommendations in an "
        f"account without Trusted Advisor API access, got {list_code!r}"
    )
    assert list_resp["ResponseMetadata"]["HTTPStatusCode"] == 403, (
        f"expected a structured 403 for the entitlement denial, got "
        f"{list_resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert list_resp["Error"].get("Message") == SUPPORT_LEVEL_DENIAL, (
        f"expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, got "
        f"{list_resp['Error'].get('Message')!r}"
    )

    well_formed_missing_arn = (
        f"arn:aws:trustedadvisor::{account_id}:recommendation/00000000-0000-0000-0000-000000000000"
    )
    get_code, get_resp = _error_code(
        lambda: ta.get_recommendation(recommendationIdentifier=well_formed_missing_arn)
    )
    assert get_code == list_code, (
        f"ListRecommendations and GetRecommendation must enforce the identical entitlement "
        f"gate for the same caller: list={list_code!r} get={get_code!r}"
    )
    assert get_resp["ResponseMetadata"]["HTTPStatusCode"] == 403, (
        f"expected a structured 403 for the entitlement denial, got "
        f"{get_resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert get_resp["Error"].get("Message") == SUPPORT_LEVEL_DENIAL, (
        f"expected GetRecommendation's denial message {SUPPORT_LEVEL_DENIAL!r}, got "
        f"{get_resp['Error'].get('Message')!r}"
    )

    # positive control: a syntactically malformed identifier is rejected for its shape, not
    # for entitlement -- proving GetRecommendation is reachable and really validating input,
    # not just failing closed for an unrelated reason (wrong region, dead credentials, a
    # network-level failure that happens to look like AccessDeniedException).
    malformed_code, malformed_resp = _error_code(
        lambda: ta.get_recommendation(recommendationIdentifier="not-an-arn-at-all-padded-out")
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a malformed identifier, got {malformed_code!r}"
    )
    assert malformed_resp["Error"].get("Message") == MALFORMED_ID_MESSAGE, (
        f"expected the exact pattern-violation message {MALFORMED_ID_MESSAGE!r}, got "
        f"{malformed_resp['Error'].get('Message')!r}"
    )
    assert malformed_code != get_code, (
        "the entitlement denial and a malformed-input rejection must not collapse to the "
        "same code"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
