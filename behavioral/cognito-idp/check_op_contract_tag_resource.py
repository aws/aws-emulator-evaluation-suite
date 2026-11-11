"""op-contract-tag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-tag-resource"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a user pool ARN visible via ListTagsForResource, and
    is rejected for an ARN that doesn't resolve to a real resource."""
    cognito = ctx.client("cognito-idp")

    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-tagres-"))[
        "UserPool"
    ]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    cognito.tag_resource(ResourceArn=pool_arn, Tags={"sim2real-team": "identity"})
    tags = cognito.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert tags.get("sim2real-team") == "identity", (
        f"expected sim2real-team=identity, got {tags.get('sim2real-team')!r} (all tags: {tags})"
    )

    # Error boundary: a well-formed but non-existent user pool ARN is rejected.
    bogus_pool_id = "us-east-1_doesnotexist99"
    bogus_arn = pool_arn.rsplit("/", 1)[0] + "/" + bogus_pool_id
    code, message = _error(
        lambda: cognito.tag_resource(ResourceArn=bogus_arn, Tags={"k": "v"})
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"User pool {bogus_pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
