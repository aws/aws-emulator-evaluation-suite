"""tag-resource-managed-billing-view-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-managed-billing-view-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on the PRIMARY billing view fail with ValidationException
    "Managed billing views cannot be tagged", while on a well-formed but nonexistent custom view arn
    both fail with ResourceNotFoundException "Resource not found"."""
    billing = ctx.client("billing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    primary_arn = _primary_view_arn(ctx)
    key = ctx.unique_name("sim2real-behav-env-")

    # control: a syntactically valid but nonexistent CUSTOM billingview ARN answers
    # ResourceNotFoundException, distinct from PRIMARY's rejection below.
    missing_arn = f"arn:aws:billing::{account_id}:billingview/custom-a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6"
    code, message = _error(
        lambda: billing.tag_resource(resourceArn=missing_arn, resourceTags=[{"key": key, "value": "x"}])
    )
    assert code == "ResourceNotFoundException", code
    assert message == "Resource not found", message

    list_code, list_message = _error(lambda: billing.list_tags_for_resource(resourceArn=missing_arn))
    assert list_code == "ResourceNotFoundException", list_code
    assert list_message == "Resource not found", list_message

    code, message = _error(
        lambda: billing.tag_resource(resourceArn=primary_arn, resourceTags=[{"key": key, "value": "x"}])
    )
    assert code == "ValidationException", code
    assert message == "Managed billing views cannot be tagged", message

    # ListTagsForResource on a managed billing view is itself rejected the
    # same way -- managed billing views carry no taggable resource surface
    # at all, consistent with TagResource's rejection above.
    list_code, list_message = _error(lambda: billing.list_tags_for_resource(resourceArn=primary_arn))
    assert list_code == "ValidationException", list_code
    assert list_message == "Managed billing views cannot be tagged", list_message


def _primary_view_arn(ctx):
    billing = ctx.client("billing")
    views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(views) == 1, f"expected exactly one PRIMARY billing view, got {len(views)}"
    return views[0]["arn"]


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


