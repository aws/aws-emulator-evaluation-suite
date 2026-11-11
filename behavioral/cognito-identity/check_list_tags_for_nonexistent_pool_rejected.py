"""list-tags-for-nonexistent-pool-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-nonexistent-pool-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource against a pool id that never existed returns a not-found
    error, while the identical call against a real pool succeeds — so the rejection is
    specific to the missing pool, not a blanket failure of the operation."""
    ci = ctx.client("cognito-identity")

    # Positive control: a real pool's own tags are listable.
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": "true"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    real_arn = _pool_arn(ctx, pool_id)
    real_tags = ci.list_tags_for_resource(ResourceArn=real_arn).get("Tags", {})
    assert real_tags == {"sim2real": "true"}, (
        f"expected the positive control's own tags back, got {real_tags!r}"
    )

    fake_pool_id = f"{ctx.region}:00000000-0000-4000-8000-000000000000"
    fake_arn = _pool_arn(ctx, fake_pool_id)

    code, message = _error(lambda: ci.list_tags_for_resource(ResourceArn=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for nonexistent pool, got {code!r}"
    )
    expected = f"IdentityPool '{fake_pool_id}' not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises, so a
    target that lists tags for a pool that never existed fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
