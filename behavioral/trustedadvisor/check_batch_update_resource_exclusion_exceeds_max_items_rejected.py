"""batch-update-resource-exclusion-exceeds-max-items-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-update-resource-exclusion-exceeds-max-items-rejected"
GROUP = "overly-permissive"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


def _fabricated_exclusion(account_id):
    return {
        "arn": f"arn:aws:trustedadvisor::{account_id}:recommendation-resource/{uuid.uuid4()}/{uuid.uuid4()}",
        "isExcluded": True,
    }


def _call(fn):
    try:
        resp = fn()
        return "OK", resp, None, 200
    except ClientError as err:
        error = err.response["Error"]
        status = err.response["ResponseMetadata"].get("HTTPStatusCode")
        return error["Code"], None, error.get("Message"), status


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 26-item BatchUpdateRecommendationResourceExclusion fails with ValidationException (HTTP 400) and the
    exact length message, while a 1-item batch and GetRecommendation fail with AccessDeniedException (HTTP
    403) "Access denied due to support level": the size limit is checked before the entitlement.
    """
    ta = ctx.client("trustedadvisor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert len(account_id) == 12 and account_id.isdigit(), (
        f"expected a resolvable 12-digit account id from STS, got {account_id!r}"
    )

    oversized_batch = [_fabricated_exclusion(account_id) for _ in range(26)]
    assert len(oversized_batch) == 26, (
        f"expected exactly 26 entries (one over the modelled 25-item max), got {len(oversized_batch)}"
    )

    code26, _, message26, status26 = _call(
        lambda: ta.batch_update_recommendation_resource_exclusion(
            recommendationResourceExclusions=oversized_batch
        )
    )
    assert code26 == "ValidationException", (
        f"expected ValidationException for a 26-item exclusion batch, got {code26!r} ({message26!r})"
    )
    assert status26 == 400, f"expected HTTP 400 for the ValidationException, got {status26!r}"
    rendered_batch = ", ".join(
        f"RecommendationResourceExclusion(arn={item['arn']}, isExcluded=true)"
        for item in oversized_batch
    )
    expected26 = (
        f"1 validation error detected: Value '[{rendered_batch}]' at "
        "'recommendationResourceExclusions' failed to satisfy constraint: "
        "Member must have length less than or equal to 25"
    )
    assert message26 == expected26, (
        f"expected the exact 25-item-max ValidationException message {expected26!r}, got {message26!r}"
    )

    # break exactly one thing: drop to a same-shape single-item batch (under the max)
    single_batch = [_fabricated_exclusion(account_id)]
    code1, _, message1, status1 = _call(
        lambda: ta.batch_update_recommendation_resource_exclusion(
            recommendationResourceExclusions=single_batch
        )
    )
    assert code1 != "ValidationException", (
        "a single-item batch (under the 25-item max) hit the same ValidationException as the "
        f"oversized batch - the API is not distinguishing by size (code={code1!r})"
    )
    assert code1 == "AccessDeniedException", (
        f"expected the account's Trusted Advisor entitlement gate (AccessDeniedException) for a "
        f"same-shape single-item batch, got {code1!r} ({message1!r})"
    )
    assert status1 == 403, f"expected HTTP 403 for the AccessDeniedException, got {status1!r}"
    assert message1 == SUPPORT_LEVEL_DENIAL, (
        f"expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, got {message1!r}"
    )

    # independent read, different operation: same blanket entitlement denial, not a quirk of
    # BatchUpdateRecommendationResourceExclusion
    fabricated_rec_arn = f"arn:aws:trustedadvisor::{account_id}:recommendation/{uuid.uuid4()}"
    code_get, _, message_get, status_get = _call(
        lambda: ta.get_recommendation(recommendationIdentifier=fabricated_rec_arn)
    )
    assert code_get == "AccessDeniedException", (
        f"expected GetRecommendation to hit the same account-wide entitlement gate, got "
        f"{code_get!r} ({message_get!r})"
    )
    assert status_get == 403, f"expected HTTP 403 for GetRecommendation's denial, got {status_get!r}"
    assert message_get == SUPPORT_LEVEL_DENIAL, (
        f"expected GetRecommendation's denial message {SUPPORT_LEVEL_DENIAL!r}, got {message_get!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
