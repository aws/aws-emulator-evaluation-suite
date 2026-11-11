"""tag-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and a follow-up ListTagsForResource on an ARN the caller does not own both fail
    AccessDeniedException with the exact IAM denial message, so no tag is persisted; ListChangeSets
    still answers, so the denial is specific to that resource."""
    # The Marketplace Catalog API is served in us-east-1 only, so the client pins that region.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    caller = ctx.client("sts", region="us-east-1").get_caller_identity()["Arn"]
    missing_id = ctx.unique_name("sim2real-behav-")
    missing_arn = "arn:aws:aws-marketplace:us-east-1:111111111111:AWSMarketplace/AmiProduct/" + missing_id
    tags = [{"Key": "sim2real-owner", "Value": "behavioral-check"}]

    code, msg = _error_code(lambda: mp.tag_resource(ResourceArn=missing_arn, Tags=tags))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {msg}"
    expected = _denied(caller, "TagResource", missing_id)
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    code2, msg2 = _error_code(lambda: mp.list_tags_for_resource(ResourceArn=missing_arn))
    assert code2 == "AccessDeniedException", f"tag must not have been persisted, got {code2}: {msg2}"
    expected2 = _denied(caller, "ListTagsForResource", missing_id)
    assert msg2 == expected2, f"expected message {expected2!r}, got {msg2!r}"

    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp, f"expected ChangeSetSummaryList in response, got {resp!r}"


def _denied(caller, action, resource):
    return (
        f"User: {caller} is not authorized to perform: aws-marketplace:{action} on resource: "
        f"{resource} because no resource-based policy allows the aws-marketplace:{action} action"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
