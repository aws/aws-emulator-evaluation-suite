"""tag-resource-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "tag-resource-lifecycle"
GROUP = 'tagging'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges tags onto a resource; ListTagsForResource reflects them; UntagResource removes specified keys."""
    ecr = ctx.client("ecr-public")
    name, resp = _create_repository(ctx, ecr)
    arn = resp["repository"]["repositoryArn"]

    ecr.tag_resource(resourceArn=arn, tags=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "fidelity"}])

    listed = ecr.list_tags_for_resource(resourceArn=arn)
    tag_map = {t["Key"]: t["Value"] for t in listed["tags"]}
    assert tag_map.get("env") == "test", f"expected env=test, got {tag_map}"
    assert tag_map.get("team") == "fidelity", f"expected team=fidelity, got {tag_map}"

    ecr.untag_resource(resourceArn=arn, tagKeys=["team"])

    listed2 = ecr.list_tags_for_resource(resourceArn=arn)
    tag_map2 = {t["Key"]: t["Value"] for t in listed2["tags"]}
    assert "team" not in tag_map2, f"expected team removed, got {tag_map2}"
    assert tag_map2.get("env") == "test", f"expected env=test to survive untag, got {tag_map2}"

    # Deletes prove gone and unusable: an independent read 404s, and a mutation on the
    # dead resource is refused rather than silently accepted.
    ecr.delete_repository(repositoryName=name)

    gone = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    expected = (
        "RepositoryNotFoundException",
        f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'",
    )
    assert (gone.get("Code"), gone.get("Message")) == expected, f"expected {expected} after delete, got {gone}"

    mutate = _err(lambda: ecr.tag_resource(resourceArn=arn, tags=[{"Key": "env", "Value": "test"}]))
    expected = (
        "RepositoryNotFoundException",
        f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'",
    )
    assert (mutate.get("Code"), mutate.get("Message")) == expected, (
        f"expected {expected} on TagResource after delete, got {mutate}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
