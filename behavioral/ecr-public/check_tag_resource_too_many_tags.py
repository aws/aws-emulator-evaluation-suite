"""tag-resource-too-many-tags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags"
GROUP = 'error-semantics'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because a target that ACCEPTS input real AWS refuses is a stronger signal than a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)

    def _cleanup():
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name, resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource landing exactly at the fixed 50-tag limit is a positive control that succeeds;
    one more past it must fail with TooManyTagsException and leave the tag set unchanged."""
    ecr = ctx.client("ecr-public")
    below_limit_tags = [{"Key": f"k{i}", "Value": "v"} for i in range(49)]
    name, resp = _create_repository(ctx, ecr, tags=below_limit_tags)
    arn = resp["repository"]["repositoryArn"]

    # Positive control: the 50th tag lands exactly at the limit and is accepted.
    ecr.tag_resource(resourceArn=arn, tags=[{"Key": "k49", "Value": "v"}])
    at_limit = ecr.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(at_limit) == 50, f"expected exactly 50 tags at the limit, got {len(at_limit)}"

    # Negative: a 51st tag pushes past the fixed limit and must be rejected.
    err = _err(
        lambda: ecr.tag_resource(resourceArn=arn, tags=[{"Key": "one-too-many", "Value": "x"}])
    )
    expected = ("TooManyTagsException", "The number of tags exceeds the limit")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    # Effect absent: the rejected call must not have mutated the tag set.
    after = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert len(after) == 50 and "one-too-many" not in after, (
        f"rejected TagResource must not mutate the tag set, got {len(after)} tags: {sorted(after)}"
    )

    ecr.delete_repository(repositoryName=name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
