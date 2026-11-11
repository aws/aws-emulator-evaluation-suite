"""tag-resource-nonexistent-resource-not-found."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against a resource ARN that does not exist returns NotFoundException."""
    s3v = ctx.client("s3vectors")
    ghost_name = ctx.unique_name("sim2real-s3v-ghost-")
    ghost_arn = f"arn:aws:s3vectors:{ctx.region}:{ctx.account}:bucket/{ghost_name}"

    err = _error(lambda: s3v.tag_resource(resourceArn=ghost_arn, tags={"k": "v"}))
    assert err["Code"] == "NotFoundException", f"expected NotFoundException tagging a ghost ARN, got {err!r}"
    assert err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact bucket not-found message, got {err.get('Message')!r}"
    )

    # effect absent: no tags were recorded for the nonexistent resource (bucket never came into being)
    list_err = _error(lambda: s3v.list_tags_for_resource(resourceArn=ghost_arn))
    assert list_err["Code"] == "NotFoundException", f"expected NotFoundException listing tags on a ghost ARN, got {list_err!r}"
    assert list_err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact bucket not-found message, got {list_err.get('Message')!r}"
    )

    # positive control: tagging a real bucket succeeds and is reflected in ListTagsForResource
    real_name = ctx.unique_name("sim2real-s3v-")
    real_arn = s3v.create_vector_bucket(vectorBucketName=real_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=real_name))
    s3v.tag_resource(resourceArn=real_arn, tags={"k": "v"})
    tags = s3v.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert tags.get("k") == "v", f"expected tag 'k'='v' on real bucket, got {tags!r}"


def _error(fn) -> dict:
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
