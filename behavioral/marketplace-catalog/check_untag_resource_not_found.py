"""untag-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource fails ValidationException for a malformed ARN and AccessDeniedException for a
    well-formed ARN the caller does not own, each with its exact message: shape validation runs before
    authorization. ListChangeSets still answers, so the denial is specific to that resource."""
    # The Marketplace Catalog API is served in us-east-1 only, so the client pins that region.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    caller = ctx.client("sts", region="us-east-1").get_caller_identity()["Arn"]
    bad_arn = "definitely-not-an-arn"
    code, msg = _error_code(lambda: mp.untag_resource(ResourceArn=bad_arn, TagKeys=["sim2real-owner"]))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {msg}"
    expected = (
        f"[Requested resource arn '{bad_arn}' is invalid. It should match with "
        + r"^arn:[\w+=/,.@-]+:aws-marketplace:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*$" + ".]"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    missing_id = ctx.unique_name("sim2real-behav-")
    good_but_missing_arn = "arn:aws:aws-marketplace:us-east-1:111111111111:AWSMarketplace/AmiProduct/" + missing_id
    code2, msg2 = _error_code(lambda: mp.untag_resource(ResourceArn=good_but_missing_arn, TagKeys=["sim2real-owner"]))
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}: {msg2}"
    expected2 = _denied(caller, "UntagResource", missing_id)
    assert msg2 == expected2, f"expected message {expected2!r}, got {msg2!r}"

    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp


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
