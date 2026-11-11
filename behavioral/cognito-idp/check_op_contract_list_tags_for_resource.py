"""op-contract-list-tags-for-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-tags-for-resource"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns exactly the tags attached to the resource ARN;
    an ARN pointing at a nonexistent pool 404s."""
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    idp.tag_resource(ResourceArn=pool_arn, Tags={"sim2real-purpose": "list-tags-check"})

    tags = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert tags.get("sim2real-purpose") == "list-tags-check", (
        f"expected sim2real-purpose=list-tags-check, got {tags.get('sim2real-purpose')!r}"
    )

    bogus_id = "us-east-1_ZZZZZZZZZ"
    bogus_arn = pool_arn[: pool_arn.rindex("/") + 1] + bogus_id
    err = _client_error(lambda: idp.list_tags_for_resource(ResourceArn=bogus_arn))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = f"User pool {bogus_id} does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
