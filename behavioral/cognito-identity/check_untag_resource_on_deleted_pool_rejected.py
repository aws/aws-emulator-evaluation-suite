"""untag-resource-on-deleted-pool-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-on-deleted-pool-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource against an already-deleted pool returns an error, not a false success."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(ci, pool_id))
    arn = _pool_arn(ctx, pool_id)
    ci.tag_resource(ResourceArn=arn, Tags={"k": "v"})

    # Positive control: UntagResource must actually work on the live pool, so the
    # ResourceNotFoundException asserted below cannot be confused with an UntagResource
    # that fails unconditionally regardless of pool state.
    ci.untag_resource(ResourceArn=arn, TagKeys=["k"])
    live_tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "k" not in live_tags, f"expected 'k' removed from live pool, got {live_tags!r}"

    ci.tag_resource(ResourceArn=arn, Tags={"k": "v"})

    # Delete the pool up front; the cleanup above then finds nothing to remove.
    ci.delete_identity_pool(IdentityPoolId=pool_id)

    code, message = _refusal(
        lambda: ci.untag_resource(ResourceArn=arn, TagKeys=["k"]),
        "UntagResource on a deleted pool",
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for UntagResource on a deleted pool, got {code!r}: "
        f"{message!r}"
    )
    expected_message = f"IdentityPool '{pool_id}' not found."
    assert message == expected_message, (
        f"expected the message {expected_message!r} for UntagResource on a deleted pool, got "
        f"{message!r}"
    )


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


def _delete_pool_if_present(ci, pool_id: str) -> None:
    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _refusal(fn, what):
    """Call fn(); return (Code, Message) when it is refused, and raise when it succeeds."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} must be refused, but the call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
