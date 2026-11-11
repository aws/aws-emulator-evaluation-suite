"""list-repository-sync-definitions-bad-link-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-repository-sync-definitions-bad-link-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRepositorySyncDefinitions on a nonexistent RepositoryLinkId raises InvalidInputException
    naming the id, while a real link without sync configuration returns an empty definition list."""
    cc = ctx.client("codeconnections")

    conn_name = ctx.unique_name("sim2real-conn-")[:32]
    conn_arn = cc.create_connection(
        ConnectionName=conn_name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    owner_id = ctx.unique_name("s2rowner")[:64]
    repo_name = ctx.unique_name("s2rrepo")[:64]
    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner_id,
        RepositoryName=repo_name,
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=link_id))

    positive = cc.list_repository_sync_definitions(
        RepositoryLinkId=link_id, SyncType="CFN_STACK_SYNC"
    )
    assert positive["RepositorySyncDefinitions"] == [], (
        "positive control: expected no sync definitions on a fresh link, got "
        + repr(positive["RepositorySyncDefinitions"])
    )

    fake_id = str(uuid.uuid4())
    code, message = _error(
        lambda: cc.list_repository_sync_definitions(
            RepositoryLinkId=fake_id, SyncType="CFN_STACK_SYNC"
        )
    )
    assert code == "InvalidInputException", "actual_code=" + str(code)
    assert message == f"Repository Link with id {fake_id} was not found", f"message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
