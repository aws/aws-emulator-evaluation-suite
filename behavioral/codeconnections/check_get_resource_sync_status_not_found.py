"""get-resource-sync-status-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-resource-sync-status-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceSyncStatus for a resource with no sync configuration succeeds with no DesiredState,
    LatestSync or LatestSuccessfulSync."""
    cc = ctx.client("codeconnections")
    resource_name = ctx.unique_name("s2rsync")[:100]

    resp = cc.get_resource_sync_status(ResourceName=resource_name, SyncType="CFN_STACK_SYNC")
    resp.pop("ResponseMetadata", None)
    assert resp == {}, "expected no sync-state fields for a never-configured resource, got " + repr(resp)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
