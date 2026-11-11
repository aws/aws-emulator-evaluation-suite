"""tag-resource-key-exceeding-length-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-key-exceeding-length-rejected"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a 129-char tag key with ValidationException (shape-length validation,
    not InvalidParameterException) and applies neither tag from the call; a valid-only call
    then succeeds."""
    cognito = ctx.client("cognito-identity")

    pool_name = ctx.unique_name("sim2real-idp-")
    created = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    resource_arn = _pool_arn(ctx, pool_id)

    too_long_key = "k" * 129  # max is 128
    valid_key = "valid-key"

    code, message = _error(
        lambda: cognito.tag_resource(
            ResourceArn=resource_arn,
            Tags={too_long_key: "some-value", valid_key: "some-other-value"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a 129-char tag key, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{{{too_long_key}=some-value, {valid_key}=some-other-value}}' "
        "at 'tags' failed to satisfy constraint: Map keys must satisfy constraint: "
        "[Member must have length less than or equal to 128, Member must have length greater than or equal to 1]"
    ), message


    # Effect absent: the whole TagResource call is atomic -- neither tag stuck.
    listed = cognito.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert too_long_key not in listed, f"oversized-key tag was unexpectedly applied: {listed!r}"
    assert valid_key not in listed, f"valid key from the rejected call was applied non-atomically: {listed!r}"

    # Positive control: a call with only valid keys/values succeeds and persists.
    cognito.tag_resource(ResourceArn=resource_arn, Tags={valid_key: "some-other-value"})
    listed_after = cognito.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert listed_after.get(valid_key) == "some-other-value", (
        f"expected {valid_key!r}='some-other-value' after a valid TagResource call, got {listed_after!r}"
    )


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because a
    target accepting a call AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
