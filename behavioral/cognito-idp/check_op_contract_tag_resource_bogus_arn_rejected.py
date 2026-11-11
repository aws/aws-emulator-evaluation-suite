"""op-contract-tag-resource-bogus-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-tag-resource-bogus-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource actually persists tags on the pool (visible via ListTagsForResource);
    tagging an ARN for a pool that doesn't exist is rejected with ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    idp.tag_resource(ResourceArn=pool_arn, Tags={"sim2real-owner": "tag-resource-check", "env": "test"})

    tags_now = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert tags_now.get("sim2real-owner") == "tag-resource-check", (
        f"expected sim2real-owner=tag-resource-check, got {tags_now.get('sim2real-owner')!r}"
    )
    assert tags_now.get("env") == "test", f"expected env=test, got {tags_now.get('env')!r}"

    bogus_pool_id = "us-east-1_ZZZZZZZZZ"
    bogus_arn = pool_arn[: pool_arn.rindex("/") + 1] + bogus_pool_id
    code, message = _error(lambda: idp.tag_resource(ResourceArn=bogus_arn, Tags={"a": "b"}))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"User pool {bogus_pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
