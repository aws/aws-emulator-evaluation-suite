"""tag-resource-and-untag."""
from __future__ import annotations

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

CHECK = "tag-resource-and-untag"
GROUP = 'tagging'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource removes
    a specific key and the removal is reflected on the next list."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    repo = _create_repo(ecr, ctx, name)
    arn = repo["repositoryArn"]

    ecr.tag_resource(
        resourceArn=arn, tags=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "core"}]
    )
    tags = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert tags == {"env": "test", "team": "core"}, f"expected {{'env': 'test', 'team': 'core'}}, got {tags}"

    ecr.untag_resource(resourceArn=arn, tagKeys=["team"])
    tags_after = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert tags_after == {"env": "test"}, f"expected {{'env': 'test'}} after untag, got {tags_after}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
