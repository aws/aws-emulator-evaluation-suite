"""list-recommendation-resources-exclusion-partition-invariant."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendation-resources-exclusion-partition-invariant"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


def _find_recommendation_with_resources(ctx):
    ta = ctx.client("trustedadvisor")
    recs = ta.list_recommendations(maxResults=25).get("recommendationSummaries", [])
    for rec in recs:
        resources = ta.list_recommendation_resources(
            recommendationIdentifier=rec["arn"], maxResults=50
        ).get("recommendationResourceSummaries", [])
        if resources:
            return rec["arn"], resources
    return None, []


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Excluded and included ListRecommendationResources results exactly partition the unfiltered set;
    without a support-level entitlement, ListRecommendations fails with AccessDeniedException (HTTP 403)
    "Access denied due to support level" instead of returning an empty catalog."""
    ta = ctx.client("trustedadvisor")
    try:
        rec_arn, all_resources = _find_recommendation_with_resources(ctx)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert code == "AccessDeniedException", (
            f"ListRecommendations: expected AccessDeniedException, got {code!r} ({message!r})"
        )
        assert message == SUPPORT_LEVEL_DENIAL, (
            f"ListRecommendations: expected the denial message {SUPPORT_LEVEL_DENIAL!r}, got {message!r}"
        )
        assert status == 403, f"ListRecommendations: expected HTTP 403 for the gate, got {status}"
        return
    if rec_arn is None:
        raise AssertionError(
            "no recommendation in this account has any associated resources to list"
        )

    included = ta.list_recommendation_resources(
        recommendationIdentifier=rec_arn, exclusionStatus="included", maxResults=50
    ).get("recommendationResourceSummaries", [])
    excluded = ta.list_recommendation_resources(
        recommendationIdentifier=rec_arn, exclusionStatus="excluded", maxResults=50
    ).get("recommendationResourceSummaries", [])

    for r in included:
        assert r["exclusionStatus"] == "included"
    for r in excluded:
        assert r["exclusionStatus"] == "excluded"

    assert len(included) + len(excluded) == len(all_resources), (
        f"included({len(included)}) + excluded({len(excluded)}) != unfiltered({len(all_resources)})"
    )
    all_arns = {r["arn"] for r in all_resources}
    split_arns = {r["arn"] for r in included} | {r["arn"] for r in excluded}
    assert all_arns == split_arns, "exclusion-partitioned resource arn set differs from unfiltered set"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
