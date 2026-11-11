"""create-repository-link-with-tags-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-repository-link-with-tags-reflected"
GROUP = "data-plane"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied with TagResource to a new repository link ARN are returned by ListTagsForResource."""
    cc = ctx.client("codeconnections")
    conn_name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(ConnectionName=conn_name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    owner_id = ctx.unique_name("s2rowner")[:64]
    repo_name = ctx.unique_name("s2rrepo")[:64]
    resp = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner_id,
        RepositoryName=repo_name,
    )
    link_info = resp["RepositoryLinkInfo"]
    link_id = link_info["RepositoryLinkId"]
    link_arn = link_info["RepositoryLinkArn"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=link_id))

    cc.tag_resource(ResourceArn=link_arn, Tags=[{"Key": "team", "Value": "sim2real"}])

    import time

    deadline = time.time() + 30
    tags = {}
    while time.time() < deadline:
        tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=link_arn)["Tags"]}
        if tags == {"team": "sim2real"}:
            break
        time.sleep(2)
    assert tags == {"team": "sim2real"}, "actual_tags=" + repr(tags)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
