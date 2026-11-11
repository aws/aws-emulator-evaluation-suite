"""delete-resource-policy-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy and GetResourcePolicy on a well-formed entity ARN the caller does not own are
    refused with AccessDeniedException and the exact message naming the caller and action, and
    ListChangeSets still works.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    missing_arn = (
        "arn:aws:aws-marketplace:us-east-1:111122223333:AWSMarketplace/AmiProduct/"
        + ctx.unique_name("sim2real-behav-")
    )
    resource = missing_arn.rsplit("/", 1)[-1]

    def denial_tail(op: str) -> str:
        return (
            f" is not authorized to perform: aws-marketplace:{op} on resource: {resource} "
            f"because no resource-based policy allows the aws-marketplace:{op} action"
        )

    # The message opens with the caller's ARN.
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()["Arn"]
    code, msg = _error_code(lambda: mp.delete_resource_policy(ResourceArn=missing_arn))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException (the caller owns no marketplace entities, so the "
        f"authorization check on a well-formed but foreign-owned ARN fails before any "
        f"existence lookup), got {code}: {msg}"
    )
    expected = f"User: {caller}{denial_tail('DeleteResourcePolicy')}"
    assert msg == expected, f"expected DeleteResourcePolicy denial {expected!r}, got {msg!r}"

    code2, msg2 = _error_code(lambda: mp.get_resource_policy(ResourceArn=missing_arn))
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}: {msg2}"
    expected = f"User: {caller}{denial_tail('GetResourcePolicy')}"
    assert msg2 == expected, f"expected GetResourcePolicy denial {expected!r}, got {msg2!r}"

    # positive control: the service is still reachable and functioning
    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp, f"expected ChangeSetSummaryList in response, got {resp!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
