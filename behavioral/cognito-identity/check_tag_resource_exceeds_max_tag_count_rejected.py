"""tag-resource-exceeds-max-tag-count-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-max-tag-count-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An identity pool can have at most 50 tags; attaching 51 in one TagResource call is
    rejected as a quota boundary, distinct from an oversized-value or reserved-key rejection."""
    cip = ctx.client("cognito-identity")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    pool_id = cip.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))
    resource_arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    too_many_tags = {f"tag-{i}": f"value-{i}" for i in range(51)}

    def _bad_call():
        cip.tag_resource(ResourceArn=resource_arn, Tags=too_many_tags)

    code, message = _error(_bad_call)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "The resultant tag set must not have more than 50 user tags.", message

    # effect absent: no tags were persisted by the rejected call
    current = cip.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert current == {}, "over-limit TagResource call must not persist any tags"

    # positive control: exactly the max of 50 tags succeeds
    max_tags = {f"tag-{i}": f"value-{i}" for i in range(50)}
    cip.tag_resource(ResourceArn=resource_arn, Tags=max_tags)
    ctx.on_cleanup(
        lambda: cip.untag_resource(ResourceArn=resource_arn, TagKeys=list(max_tags.keys()))
    )
    after = cip.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert after == max_tags, "exactly 50 tags must persist"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
