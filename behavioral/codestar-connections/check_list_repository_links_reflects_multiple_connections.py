"""list-repository-links-reflects-multiple-connections."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-repository-links-reflects-multiple-connections"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRepositoryLinks correctly maps each link's fields back to its own connection,
    rather than collapsing or mixing up records when multiple links exist.
    """
    cc = ctx.client("codestar-connections")

    tags = [{"Key": "sim2real-purpose", "Value": "behavioral-check"}]

    conn1 = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-c1-")[:32], ProviderType="GitHub", Tags=tags
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn1))
    conn2 = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-c2-")[:32], ProviderType="GitHub", Tags=tags
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn2))

    owner1, repo1 = ctx.unique_name("sim2real-owner1-"), ctx.unique_name("sim2real-repo1-")
    owner2, repo2 = ctx.unique_name("sim2real-owner2-"), ctx.unique_name("sim2real-repo2-")

    link1_id = cc.create_repository_link(
        ConnectionArn=conn1, OwnerId=owner1, RepositoryName=repo1, Tags=tags
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link1_id))

    link2_id = cc.create_repository_link(
        ConnectionArn=conn2, OwnerId=owner2, RepositoryName=repo2, Tags=tags
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link2_id))

    links = {link["RepositoryLinkId"]: link for link in cc.list_repository_links()["RepositoryLinks"]}

    assert links[link1_id]["ConnectionArn"] == conn1, (
        f"link1 ConnectionArn expected {conn1!r}, got {links[link1_id]['ConnectionArn']!r}"
    )
    assert links[link1_id]["OwnerId"] == owner1, (
        f"link1 OwnerId expected {owner1!r}, got {links[link1_id]['OwnerId']!r}"
    )
    assert links[link1_id]["RepositoryName"] == repo1, (
        f"link1 RepositoryName expected {repo1!r}, got {links[link1_id]['RepositoryName']!r}"
    )

    assert links[link2_id]["ConnectionArn"] == conn2, (
        f"link2 ConnectionArn expected {conn2!r}, got {links[link2_id]['ConnectionArn']!r}"
    )
    assert links[link2_id]["OwnerId"] == owner2, (
        f"link2 OwnerId expected {owner2!r}, got {links[link2_id]['OwnerId']!r}"
    )
    assert links[link2_id]["RepositoryName"] == repo2, (
        f"link2 RepositoryName expected {repo2!r}, got {links[link2_id]['RepositoryName']!r}"
    )


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_repository_link(cc, link_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_repository_link(RepositoryLinkId=link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
