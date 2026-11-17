"""tag-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource and ListTagsForResource with a ResourceArn that is not an ARN
    at all each fail BadRequestException with "Invalid input resource arn: bad syntax".
    """
    msk = ctx.client("kafka")

    # Positive control: the client, credentials and service are generally healthy, so the
    # rejections below are about the malformed ARN, not about every call failing.
    msk.list_clusters_v2()

    expected = ("BadRequestException", "Invalid input resource arn: bad syntax")

    tag_err = _err(lambda: msk.tag_resource(ResourceArn="not-an-arn", Tags={"env": "sim2real"}))
    assert tag_err == expected, tag_err

    untag_err = _err(lambda: msk.untag_resource(ResourceArn="not-an-arn", TagKeys=["env"]))
    assert untag_err == expected, untag_err

    list_err = _err(lambda: msk.list_tags_for_resource(ResourceArn="not-an-arn"))
    assert list_err == expected, list_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
