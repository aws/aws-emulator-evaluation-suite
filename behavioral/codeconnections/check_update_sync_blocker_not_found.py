"""update-sync-blocker-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-sync-blocker-not-found"
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
    """UpdateSyncBlocker for a resource with no sync configuration raises
    SyncBlockerDoesNotExistException naming the blocker id: the id is checked before the resource."""
    cc = ctx.client("codeconnections")
    resource_name = ctx.unique_name("s2rsync")[:100]

    code, message = _error(
        lambda: cc.update_sync_blocker(
            Id="blocker-1",
            SyncType="CFN_STACK_SYNC",
            ResourceName=resource_name,
            ResolvedReason="sim2real-behavioral-test",
        )
    )
    assert code == "SyncBlockerDoesNotExistException", "actual_code=" + str(code)
    # AWS's message carries a trailing space.
    assert message == "Sync blocker with id blocker-1 does not exist ", f"message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
