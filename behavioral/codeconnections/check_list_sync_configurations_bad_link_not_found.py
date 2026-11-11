"""list-sync-configurations-bad-link-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-sync-configurations-bad-link-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        "expected ListSyncConfigurations to be rejected, but it succeeded: " + repr(result)
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSyncConfigurations on a nonexistent RepositoryLinkId raises InvalidInputException, while the
    identical call on a real link returns an empty list."""
    cc = ctx.client("codeconnections")

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-conn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    link_id = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=ctx.unique_name("s2rowner")[:32],
        RepositoryName=ctx.unique_name("s2rrepo")[:32],
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["RepositoryLinkInfo"]["RepositoryLinkId"]
    ctx.on_cleanup(lambda: cc.delete_repository_link(RepositoryLinkId=link_id))

    # positive control: a real RepositoryLinkId succeeds and reports no configurations
    resp = cc.list_sync_configurations(RepositoryLinkId=link_id, SyncType="CFN_STACK_SYNC")
    assert resp["SyncConfigurations"] == [], (
        "expected no sync configurations for a freshly created link, got "
        + str(resp["SyncConfigurations"])
    )

    # negative: a RepositoryLinkId that was never created is rejected
    fake_id = str(uuid.uuid4())
    code, message = _error_code(
        lambda: cc.list_sync_configurations(RepositoryLinkId=fake_id, SyncType="CFN_STACK_SYNC")
    )
    assert code == "InvalidInputException", "actual_code=" + str(code)
    expected = f"Repository Link with id {fake_id} was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
