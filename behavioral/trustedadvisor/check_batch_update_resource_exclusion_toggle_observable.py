"""batch-update-resource-exclusion-toggle-observable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-update-resource-exclusion-toggle-observable"
GROUP = "resource-exclusion"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


def _find_resource(ctx):
    ta = ctx.client("trustedadvisor")
    recs = ta.list_recommendations(maxResults=25).get("recommendationSummaries", [])
    for rec in recs:
        resources = ta.list_recommendation_resources(
            recommendationIdentifier=rec["arn"], maxResults=10
        ).get("recommendationResourceSummaries", [])
        if resources:
            return rec["arn"], resources[0]
    return None, None


def _poll_exclusion_status(ctx, rec_arn, resource_arn, expected_status, timeout_s=30.0):
    ta = ctx.client("trustedadvisor")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resources = ta.list_recommendation_resources(
            recommendationIdentifier=rec_arn, maxResults=50
        ).get("recommendationResourceSummaries", [])
        match = next((r for r in resources if r["arn"] == resource_arn), None)
        last = match["exclusionStatus"] if match else None
        if last == expected_status:
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"exclusionStatus for {resource_arn} never reached {expected_status!r}, last seen {last!r}"
    )


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """Excluding then re-including a resource with BatchUpdateRecommendationResourceExclusion shows
    in ListRecommendationResources; without a support-level entitlement, the reads and the batch
    update fail with AccessDeniedException "Access denied due to support level"."""
    ta = ctx.client("trustedadvisor")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    assert account_id, "sts get-caller-identity returned no account id - credentials are unhealthy"

    try:
        rec_arn, resource = _find_resource(ctx)
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "AccessDeniedException", (
            f"expected AccessDeniedException for a caller lacking a TA support plan, got {error!r}"
        )
        message = error.get("Message")
        assert message == SUPPORT_LEVEL_DENIAL, (
            f"expected the refusal message {SUPPORT_LEVEL_DENIAL!r}, got {message!r}"
        )

        checks_code, checks_msg = _error(lambda: ta.list_checks(maxResults=1))
        assert checks_code == "AccessDeniedException", (
            f"expected ListChecks to be denied identically (an account-wide entitlement "
            f"gate, not a permission gap on ListRecommendations alone), got {checks_code!r}"
        )
        assert checks_msg == SUPPORT_LEVEL_DENIAL, (
            f"expected ListChecks' denial message {SUPPORT_LEVEL_DENIAL!r}, got {checks_msg!r}"
        )

        placeholder_arn = (
            f"arn:aws:trustedadvisor::{account_id}:recommendation-resource/"
            "00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000"
        )
        batch_code, batch_msg = _error(
            lambda: ta.batch_update_recommendation_resource_exclusion(
                recommendationResourceExclusions=[{"arn": placeholder_arn, "isExcluded": True}]
            )
        )
        assert batch_code == "AccessDeniedException", (
            f"expected BatchUpdateRecommendationResourceExclusion -- the operation this "
            f"check names -- to be denied identically even against a nonexistent resource "
            f"ARN, got {batch_code!r}"
        )
        assert batch_msg == SUPPORT_LEVEL_DENIAL, (
            f"expected BatchUpdateRecommendationResourceExclusion's denial message "
            f"{SUPPORT_LEVEL_DENIAL!r}, got {batch_msg!r}"
        )
        return
    if rec_arn is None:
        raise AssertionError(
            "no recommendation in this account has any associated resources to exclude"
        )
    resource_arn = resource["arn"]
    original_status = resource["exclusionStatus"]

    def _restore():
        ta.batch_update_recommendation_resource_exclusion(
            recommendationResourceExclusions=[
                {"arn": resource_arn, "isExcluded": original_status == "excluded"}
            ]
        )

    ctx.on_cleanup(_restore)

    # exclude it
    resp = ta.batch_update_recommendation_resource_exclusion(
        recommendationResourceExclusions=[{"arn": resource_arn, "isExcluded": True}]
    )
    errors = resp["batchUpdateRecommendationResourceExclusionErrors"]
    assert errors == [], f"expected no exclusion errors excluding {resource_arn!r}, got {errors!r}"
    _poll_exclusion_status(ctx, rec_arn, resource_arn, "excluded")

    # include it back
    resp = ta.batch_update_recommendation_resource_exclusion(
        recommendationResourceExclusions=[{"arn": resource_arn, "isExcluded": False}]
    )
    errors = resp["batchUpdateRecommendationResourceExclusionErrors"]
    assert errors == [], f"expected no exclusion errors including {resource_arn!r}, got {errors!r}"
    _poll_exclusion_status(ctx, rec_arn, resource_arn, "included")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
