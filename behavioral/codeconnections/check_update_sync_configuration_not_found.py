"""update-sync-configuration-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-sync-configuration-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSyncConfiguration for a ResourceName with no sync configuration is rejected."""
    cc = ctx.client("codeconnections")
    resource_name = ctx.unique_name("s2rsync")

    code, message = _error(
        lambda: cc.update_sync_configuration(
            ResourceName=resource_name, SyncType="CFN_STACK_SYNC", Branch="main"
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    assert message == f"Sync Configuration for Resource {resource_name} was not found", (
        f"message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
