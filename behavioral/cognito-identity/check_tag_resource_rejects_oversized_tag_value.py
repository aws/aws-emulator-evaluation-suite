"""tag-resource-rejects-oversized-tag-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejects-oversized-tag-value"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag value beyond the documented 256-char limit rather than truncating it."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    arn = _pool_arn(ctx, pool_id)

    # Positive control: an in-bounds tag value is accepted and persists.
    ci.tag_resource(ResourceArn=arn, Tags={"valid-key": "valid-value"})
    tags_before = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_before.get("valid-key") == "valid-value", (
        f"expected the in-bounds tag to persist, got {tags_before!r}"
    )

    oversized_value = "v" * 300  # documented max tag value length is 256
    code, message = _error(
        lambda: ci.tag_resource(ResourceArn=arn, Tags={"oversize-key": oversized_value})
    )
    assert code == "ValidationException", (
        f"expected ValidationException for oversized tag value, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{{oversize-key={oversized_value}}}' at 'tags' failed "
        "to satisfy constraint: Map value must satisfy constraint: "
        "[Member must have length less than or equal to 256, Member must have length greater than or equal to 0]"
    ), message

    # The rejected write must not be silently truncated and applied.
    tags_after = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "oversize-key" not in tags_after, (
        f"rejected tag was unexpectedly applied (possibly truncated): {tags_after}"
    )


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded with {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
