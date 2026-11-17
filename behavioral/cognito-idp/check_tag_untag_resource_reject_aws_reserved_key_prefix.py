"""tag-untag-resource-reject-aws-reserved-key-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-reject-aws-reserved-key-prefix"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_SYSTEM_TAG = (
    "InvalidParameterException",
    "Caller is an end user and not allowed to mutate system tags",
)


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        actual = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return
    raise AssertionError(f"expected the call to be refused with {(code, message)!r}, got {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and UntagResource refuse a tag key under the aws: prefix with its exact
    system-tag message, and the key never reaches ListTagsForResource; an ordinary key still
    tags, lists and untags on the same pool."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    arn = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["Arn"]

    # An ordinary key tags cleanly.
    c.tag_resource(ResourceArn=arn, Tags={"sim2real-ordinary": "kept"})
    tagged = c.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tagged.get("sim2real-ordinary") == "kept", (
        f"expected sim2real-ordinary=kept after TagResource, got {tagged!r}"
    )

    # TagResource refuses a key under the aws: reserved prefix with its exact message.
    _expect_error(
        lambda: c.tag_resource(ResourceArn=arn, Tags={"aws:sim2real-reserved": "x"}),
        *_SYSTEM_TAG,
    )
    after_tag_refusal = c.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "aws:sim2real-reserved" not in after_tag_refusal, (
        f"a refused aws: key must never reach ListTagsForResource, got {after_tag_refusal!r}"
    )
    assert after_tag_refusal.get("sim2real-ordinary") == "kept", (
        f"the refusal must leave the ordinary tag untouched, got {after_tag_refusal!r}"
    )

    # UntagResource refuses the same key form with the same exact message.
    _expect_error(
        lambda: c.untag_resource(ResourceArn=arn, TagKeys=["aws:sim2real-reserved"]),
        *_SYSTEM_TAG,
    )
    after_untag_refusal = c.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "aws:sim2real-reserved" not in after_untag_refusal, (
        f"a refused aws: key must stay absent from ListTagsForResource, got {after_untag_refusal!r}"
    )
    assert after_untag_refusal.get("sim2real-ordinary") == "kept", (
        f"the refusal must leave the ordinary tag untouched, got {after_untag_refusal!r}"
    )

    # The ordinary key still untags cleanly on the same pool.
    c.untag_resource(ResourceArn=arn, TagKeys=["sim2real-ordinary"])
    final = c.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-ordinary" not in final, f"expected sim2real-ordinary removed, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
