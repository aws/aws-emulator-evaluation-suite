"""tag-untag-resource-malformed-arn-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-malformed-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]

_BAD_ARN = ("BadRequestException", "Invalid input resource arn: bad syntax")
_NOT_FOUND = ("NotFoundException", "Resource was not found")


def expect_error(fn: Callable[[], Any], code: str, message: str) -> None:
    """Call fn, require it raises a ClientError whose (Code, Message) is exactly this pair."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and UntagResource both reject a resourceArn that is not ARN-shaped with
    BadRequestException, distinct from the NotFoundException a well-formed but absent ARN gets.
    """
    eks = ctx.client("eks")
    well_formed_arn = (
        f"arn:aws:eks:{ctx.region}:{ctx.account}:cluster/{ctx.unique_name('sim2real-eks-nocluster-')}"
    )

    expect_error(
        lambda: eks.tag_resource(resourceArn="not-an-arn", tags={"k": "v"}),
        *_BAD_ARN,
    )
    # Positive control: an ARN-shaped resourceArn passes syntax validation and the call
    # fails for a later, different reason -- the resource does not exist.
    expect_error(
        lambda: eks.tag_resource(resourceArn=well_formed_arn, tags={"k": "v"}),
        *_NOT_FOUND,
    )

    expect_error(
        lambda: eks.untag_resource(resourceArn="not-an-arn", tagKeys=["k"]),
        *_BAD_ARN,
    )
    expect_error(
        lambda: eks.untag_resource(resourceArn=well_formed_arn, tagKeys=["k"]),
        *_NOT_FOUND,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
