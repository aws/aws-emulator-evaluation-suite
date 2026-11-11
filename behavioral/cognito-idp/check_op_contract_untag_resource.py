"""op-contract-untag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-untag-resource"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource actually removes the tag key (not just returns 200) while leaving
    other tags intact; untagging a bogus ARN 404s."""
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    idp.tag_resource(ResourceArn=pool_arn, Tags={"sim2real-remove-me": "yes", "sim2real-keep-me": "yes"})
    before = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert "sim2real-remove-me" in before and "sim2real-keep-me" in before, (
        f"positive control: expected both tags visible via ListTagsForResource, got {before}"
    )

    idp.untag_resource(ResourceArn=pool_arn, TagKeys=["sim2real-remove-me"])

    after = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert "sim2real-remove-me" not in after, (
        f"expected sim2real-remove-me gone after UntagResource, still present in {after}"
    )
    assert after.get("sim2real-keep-me") == "yes", (
        f"expected sim2real-keep-me=yes to survive the untag of the other key, got {after}"
    )

    bogus_pool_id = "us-east-1_ZZZZZZZZZ"
    bogus_arn = pool_arn[: pool_arn.rindex("/") + 1] + bogus_pool_id
    code, message = _error(lambda: idp.untag_resource(ResourceArn=bogus_arn, TagKeys=["a"]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"User pool {bogus_pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its Error.Code and Error.Message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
