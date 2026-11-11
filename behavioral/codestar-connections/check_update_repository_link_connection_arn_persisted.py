"""update-repository-link-connection-arn-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-repository-link-connection-arn-persisted"
GROUP = "repository-link"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRepositoryLink re-pointing ConnectionArn is durably persisted."""
    csc = ctx.client("codestar-connections")

    tags = [{"Key": "sim2real-check", "Value": "update-repository-link-connection-arn-persisted"}]

    conn1_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-c1-"), ProviderType="GitHub", Tags=tags
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn1_arn))
    conn2_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-c2-"), ProviderType="GitHub", Tags=tags
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=conn2_arn))

    link = csc.create_repository_link(
        ConnectionArn=conn1_arn,
        OwnerId="sim2real-owner",
        RepositoryName=ctx.unique_name("sim2real-behav-repo-"),
        Tags=tags,
    )["RepositoryLinkInfo"]
    link_id = link["RepositoryLinkId"]
    ctx.on_cleanup(lambda: csc.delete_repository_link(RepositoryLinkId=link_id))
    assert link["ConnectionArn"] == conn1_arn, link

    updated = csc.update_repository_link(RepositoryLinkId=link_id, ConnectionArn=conn2_arn)[
        "RepositoryLinkInfo"
    ]
    assert updated["ConnectionArn"] == conn2_arn, updated

    fetched = csc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert fetched["ConnectionArn"] == conn2_arn, fetched


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
