"""tag-resource-empty-tags-map-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-empty-tags-map-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]

_EMPTY_TAGS = ("BadRequestException", "Invalid request input, expected non-empty tags map")
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
    """TagResource with an empty tags map is rejected with BadRequestException before the
    named resource is even looked up.
    """
    eks = ctx.client("eks")
    resource_arn = (
        f"arn:aws:eks:{ctx.region}:{ctx.account}:cluster/{ctx.unique_name('sim2real-eks-nocluster-')}"
    )

    expect_error(
        lambda: eks.tag_resource(resourceArn=resource_arn, tags={}),
        *_EMPTY_TAGS,
    )

    # Positive control: a non-empty tags map passes this validation and the call fails
    # for a later, different reason -- the resource does not exist -- which shows the
    # rejection above is specific to the empty map, not every call on this made-up ARN.
    expect_error(
        lambda: eks.tag_resource(resourceArn=resource_arn, tags={"k": "v"}),
        *_NOT_FOUND,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
