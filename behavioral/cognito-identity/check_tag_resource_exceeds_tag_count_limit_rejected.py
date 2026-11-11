"""tag-resource-exceeds-tag-count-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-tag-count-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attempting to attach more than the documented 50-tag maximum to an
    identity pool is rejected as InvalidParameterException, and none of the offending
    tags are persisted -- while a single valid tag still attaches cleanly."""
    cip = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=True
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    # Positive control: a single valid tag attaches successfully.
    cip.tag_resource(ResourceArn=resource_arn, Tags={"env": "sim2real-behav"})
    tags = cip.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert tags == {"env": "sim2real-behav"}, f"expected the control tag to attach, got {tags}"

    # Break exactly one thing: exceed the documented 50-tags-per-resource maximum.
    too_many_tags = {f"sim2real-tag-{i}": "v" for i in range(51)}
    code, message = _error(lambda: cip.tag_resource(ResourceArn=resource_arn, Tags=too_many_tags))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "The resultant tag set must not have more than 50 user tags.", message

    # Effect absent: the pool's tags are unchanged -- still just the one control tag.
    after = cip.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert after == {"env": "sim2real-behav"}, (
        f"expected the rejected call to leave existing tags untouched, got {after}"
    )


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
