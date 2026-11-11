"""get-resource-policy-not-found-when-unshared."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-resource-policy-not-found-when-unshared"
GROUP = "resource-policy"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on the PRIMARY billing view fails with ResourceNotFoundException "The custom
    billing view does not exist.", as only custom views carry a policy, while GetBillingView resolves
    the same arn."""
    billing = ctx.client("billing")
    primary_arn = _primary_view_arn(ctx)

    error = _client_error(lambda: billing.get_resource_policy(resourceArn=primary_arn))
    code = error["Error"]["Code"]
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    message = error["Error"].get("Message", "")
    assert message == "The custom billing view does not exist.", message

    # positive control: the resource itself is real and readable
    detail = billing.get_billing_view(arn=primary_arn)["billingView"]
    assert detail["arn"] == primary_arn, (
        f"expected GetBillingView to resolve {primary_arn}, got {detail.get('arn')!r}"
    )


def _primary_view_arn(ctx):
    billing = ctx.client("billing")
    views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(views) == 1, f"expected exactly one PRIMARY billing view, got {len(views)}"
    return views[0]["arn"]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"expected GetResourcePolicy to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

