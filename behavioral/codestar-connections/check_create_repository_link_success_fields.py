"""create-repository-link-success-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-repository-link-success-fields"
GROUP = "repository-link"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepositoryLink on a PENDING GitHub connection succeeds, and GetRepositoryLink returns its id,
    connection ARN, owner, repository name and GitHub provider type.
    """
    csc = ctx.client("codestar-connections")
    conn_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"), ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn_arn))

    owner = "sim2real-owner"
    repo = ctx.unique_name("sim2real-behav-repo-")
    created = csc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo
    )["RepositoryLinkInfo"]
    link_id = created["RepositoryLinkId"]
    ctx.on_cleanup(lambda: csc.delete_repository_link(RepositoryLinkId=link_id))

    fetched = csc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert fetched["RepositoryLinkId"] == link_id, fetched
    assert fetched["ConnectionArn"] == conn_arn, fetched
    assert fetched["OwnerId"] == owner, fetched
    assert fetched["RepositoryName"] == repo, fetched
    assert fetched["ProviderType"] == "GitHub", fetched


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
