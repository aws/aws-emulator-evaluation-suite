"""get-repository-sync-status-without-history-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-repository-sync-status-without-history-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRepositorySyncStatus for a branch that has never had a sync attempt is rejected,
    even though the repository link itself is perfectly valid and retrievable.
    """
    cc = ctx.client("codestar-connections")

    tag_set = [{"Key": "sim2real-check", "Value": "get-repository-sync-status-without-history-rejected"}]

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32], ProviderType="GitHub", Tags=tag_set
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo, Tags=tag_set
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link_id))

    err = _error(
        lambda: cc.get_repository_sync_status(
            Branch="main", RepositoryLinkId=link_id, SyncType="CFN_STACK_SYNC"
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a branch with no sync history, got {err!r}"
    )
    assert err["Message"] == f"Could not find a sync status for repository link: {link_id}", (
        err["Message"]
    )

    # positive control: the repository link itself is valid and reachable
    info = cc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert info["RepositoryLinkId"] == link_id, (
        f"expected repository link {link_id!r} to remain reachable, got {info!r}"
    )


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
