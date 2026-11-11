"""list-distributions-by-owned-resource-filters-correctly."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-owned-resource-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByOwnedResource answers a nonexistent vpcorigin ARN with EntityNotFound, a
    malformed ARN with InvalidArgument, and a well-formed ARN of an unsupported resource type
    (connection-group) with InvalidArgument; each with its exact message."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    nonexistent_vpc_origin_arn = f"arn:aws:cloudfront::{account_id}:vpcorigin/sim2real-behav-nonexistent"
    code, message = _error_code_and_message(
        lambda: cf.list_distributions_by_owned_resource(ResourceArn=nonexistent_vpc_origin_arn)
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code!r}"
    assert message == "The specified resource doesn't exist. Update your request and try again.", (
        f"unexpected message {message!r}"
    )

    code, message = _error_code_and_message(lambda: cf.list_distributions_by_owned_resource(ResourceArn="not-an-arn"))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "Resource has invalid syntax: ARNs must start with 'arn:': not-an-arn", (
        f"unexpected message {message!r}"
    )

    # A well-formed ARN of a different CloudFront resource type is refused for its type, like a
    # malformed string, not routed into the EntityNotFound path vpcorigin takes.
    wrong_type_arn = f"arn:aws:cloudfront::{account_id}:connection-group/sim2real-behav-nonexistent"
    code, message = _error_code_and_message(lambda: cf.list_distributions_by_owned_resource(ResourceArn=wrong_type_arn))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "Invalid parameter received. Resource Type", f"unexpected message {message!r}"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
