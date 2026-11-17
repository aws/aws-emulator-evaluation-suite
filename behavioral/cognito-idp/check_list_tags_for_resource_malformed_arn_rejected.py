"""list-tags-for-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-rejected"
GROUP = "validation"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource reads a real pool's tags by its ARN and rejects a well-typed
    string that isn't ARN-shaped with InvalidParameterException and its exact message."""
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # Positive control: the real ARN resolves and carries the tags set at creation.
    live = idp.list_tags_for_resource(ResourceArn=pool_arn)
    assert live["Tags"].get("sim2real:managed") == "true", (
        f"expected sim2real:managed=true, got {live['Tags'].get('sim2real:managed')!r}"
    )

    not_an_arn = "this-is-not-an-arn-at-all-" + ctx.unique_name("sim2real")
    code, message = _error(lambda: idp.list_tags_for_resource(ResourceArn=not_an_arn))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = f"Invalid user pool ARN: {not_an_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
