"""tag-resource-reserved-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects tag keys using the reserved 'aws:' prefix."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    arn = _pool_arn(ctx, pool_id)

    # Positive control: an ordinary key must be accepted, so the negative below proves
    # the reserved prefix is specifically rejected, not that tagging is broken outright.
    ci.tag_resource(ResourceArn=arn, Tags={"ordinary-key": "x"})
    control_tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert control_tags.get("ordinary-key") == "x", (
        f"positive control failed: expected the ordinary tag to be stored, got {control_tags}"
    )

    code, message = _error(lambda: ci.tag_resource(ResourceArn=arn, Tags={"aws:reserved-key": "x"}))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Caller is an end user and not allowed to mutate system tags", message

    tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "aws:reserved-key" not in tags, "reserved-prefix tag must not have been applied"
    assert tags.get("ordinary-key") == "x", (
        f"expected the earlier ordinary tag to remain untouched, got {tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
