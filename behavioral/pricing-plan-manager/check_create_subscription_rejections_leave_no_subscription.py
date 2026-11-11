"""create-subscription-rejections-leave-no-subscription."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-subscription-rejections-leave-no-subscription"
GROUP = "validation"
SERVICES = ["pricing-plan-manager"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSubscription refuses an unrecognized plan family, an unoffered plan tier and an
    oversized resourceArns list, and none of the three refusals creates a subscription.
    """
    ppm = ctx.client("pricing-plan-manager")
    marker = ctx.unique_name("sim2real-behav-ppm-")
    cf_arn = f"arn:aws:cloudfront::{ctx.account}:distribution/{marker}"
    waf_arn = (
        f"arn:aws:wafv2:us-east-1:{ctx.account}:global/webacl/{marker}/"
        "11111111-1111-1111-1111-111111111111"
    )

    code, message = _error(
        lambda: ppm.create_subscription(
            planFamily="NotARealPlanFamily", planTier="PRO", resourceArns=[cf_arn, waf_arn]
        )
    )
    assert code == "ValidationException", (
        f"bad plan family: expected ValidationException, got {code}: {message!r}"
    )
    assert message == "Invalid plan name: NotARealPlanFamily", f"unexpected message {message!r}"

    code, message = _error(
        lambda: ppm.create_subscription(
            planFamily="CloudFront", planTier="NotARealPlanTier", resourceArns=[cf_arn, waf_arn]
        )
    )
    assert code == "ValidationException", (
        f"bad plan tier: expected ValidationException, got {code}: {message!r}"
    )
    assert message == 'Invalid plan tier "NotARealPlanTier" for the plan "CF_FRP"', (
        f"unexpected message {message!r}"
    )

    too_many = [f"arn:aws:cloudfront::{ctx.account}:distribution/{marker}-{i}" for i in range(11)]
    code, message = _error(
        lambda: ppm.create_subscription(
            planFamily="CloudFront", planTier="PRO", resourceArns=too_many
        )
    )
    assert code == "ValidationException", (
        f"oversized list: expected ValidationException, got {code}: {message!r}"
    )
    expected = (
        "1 validation error detected: Value '[" + ", ".join(too_many) + "]' at 'resourceArns' "
        "failed to satisfy constraint: Member must have length less than or equal to 10"
    )
    assert message == expected, f"unexpected message {message!r}"

    found = []
    for page in ppm.get_paginator("list_subscriptions").paginate():
        for summary in page["subscriptionSummaries"]:
            found.extend(summary.get("resourceArns", []))
    leaked = [arn for arn in found if marker in arn]
    assert leaked == [], f"a rejected CreateSubscription left resources behind: {leaked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
