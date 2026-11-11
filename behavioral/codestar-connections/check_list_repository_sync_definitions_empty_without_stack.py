"""list-repository-sync-definitions-empty-without-stack."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-repository-sync-definitions-empty-without-stack"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRepositorySyncDefinitions on a repository link that has never had a sync
    definition committed to its repository returns an empty list rather than erroring; the
    same call against a RepositoryLinkId that does not exist is rejected.
    """
    cc = ctx.client("codestar-connections")

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32], ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn, OwnerId=owner, RepositoryName=repo
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link_id))

    resp = cc.list_repository_sync_definitions(RepositoryLinkId=link_id, SyncType="CFN_STACK_SYNC")
    defs = resp["RepositorySyncDefinitions"]
    assert isinstance(defs, list), f"expected a list, got {type(defs)!r}"
    assert defs == [], f"expected no sync definitions on a fresh link, got {defs!r}"

    fake_link_id = "00000000-0000-0000-0000-000000000000"
    err = _error(
        lambda: cc.list_repository_sync_definitions(
            RepositoryLinkId=fake_link_id, SyncType="CFN_STACK_SYNC"
        )
    )
    assert err["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err!r}"
    assert err["Message"] == f"Repository Link with id {fake_link_id} was not found", err["Message"]


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises, because an emulator accepting
    input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
