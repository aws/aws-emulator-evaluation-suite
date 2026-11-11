"""tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-not-found"
GROUP = 'tags'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource and ListTagsForResource on a nonexistent cluster ARN all raise
    NotFoundException, rather than succeeding silently, no-op'ing, or returning an empty tag map."""
    msk = ctx.client("kafka")
    ghost = _bogus_cluster_arn(ctx)

    expected = ("NotFoundException", "Resource was not found")

    tag_err = _err(lambda: msk.tag_resource(ResourceArn=ghost, Tags={"sim2real": "behav"}))
    assert tag_err == expected, f"TagResource: expected {expected!r}, got {tag_err!r}"

    untag_err = _err(lambda: msk.untag_resource(ResourceArn=ghost, TagKeys=["sim2real"]))
    assert untag_err == expected, f"UntagResource: expected {expected!r}, got {untag_err!r}"

    list_err = _err(lambda: msk.list_tags_for_resource(ResourceArn=ghost))
    assert list_err == expected, f"ListTagsForResource: expected {expected!r}, got {list_err!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
