"""repository-link-uniqueness-under-concurrent-create."""
from __future__ import annotations

import concurrent.futures

from behavioral_harness import tags

CHECK = "repository-link-uniqueness-under-concurrent-create"
GROUP = "concurrency"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateRepositoryLink calls for the identical connection/owner/repository
    triple must yield exactly one repository link -- the uniqueness constraint holds under
    contention even though the exact winner and the loser's error code are not guaranteed.
    """
    cc = ctx.client("codestar-connections")

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")

    def attempt(_):
        from botocore.exceptions import ClientError

        try:
            link_id = cc.create_repository_link(
                ConnectionArn=conn_arn,
                OwnerId=owner,
                RepositoryName=repo,
                Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
            )["RepositoryLinkInfo"]["RepositoryLinkId"]
            return ("ok", link_id)
        except ClientError as exc:
            return ("err", exc.response["Error"]["Code"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, range(6)))

    successes = [r[1] for r in results if r[0] == "ok"]
    assert len(successes) >= 1, "no racer succeeded in creating the repository link"

    distinct_link_ids = set(successes)
    assert len(distinct_link_ids) == 1, f"expected exactly one repository link, got {distinct_link_ids}"

    for link_id in distinct_link_ids:
        ctx.on_cleanup(lambda link_id=link_id: _safe_delete_repository_link(cc, link_id))

    links = cc.list_repository_links()["RepositoryLinks"]
    matching = [
        link
        for link in links
        if link["ConnectionArn"] == conn_arn and link["OwnerId"] == owner and link["RepositoryName"] == repo
    ]
    assert len(matching) == 1, f"expected exactly 1 link for this triple in list_repository_links, got {len(matching)}"


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
