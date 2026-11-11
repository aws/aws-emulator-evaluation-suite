"""resource-data-sync-list-and-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-data-sync-list-and-not-found"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ResourceDataSync is listed after create and deletable; deleting it again is rejected with
    ResourceDataSyncNotFoundException and the sync stays absent from ListResourceDataSync."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected the call to raise, it succeeded")

    sync_name = ctx.unique_name("sim2real-behav-sync-")
    sync_source = {
        "SourceType": "SingleAccountMultiRegions",
        "SourceRegions": [ctx.region],
        "IncludeFutureRegions": False,
    }

    ssm.create_resource_data_sync(
        SyncName=sync_name, SyncType="SyncFromSource", SyncSource=sync_source
    )
    ctx.on_cleanup(lambda: _delete_if_present(ssm, sync_name))

    item = _poll_for_sync(ssm, sync_name)
    assert item is not None, f"{sync_name} never appeared in ListResourceDataSync after create"

    ssm.delete_resource_data_sync(SyncName=sync_name, SyncType="SyncFromSource")

    code, message = _error_code(
        lambda: ssm.delete_resource_data_sync(SyncName=sync_name, SyncType="SyncFromSource")
    )
    assert code == "ResourceDataSyncNotFoundException", (
        f"expected ResourceDataSyncNotFoundException deleting an already-deleted sync, got {code}"
    )
    assert message == f"ResourceDataSync with name {sync_name} synctype SyncFromSource does not exists", message

    survivor = _poll_for_absence(ssm, sync_name)
    assert survivor is None, f"{sync_name} is still listed after two deletes: {survivor}"


def _find_sync(ssm, sync_name: str):
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        # SyncType defaults to SyncToDestination (S3); SyncFromSource syncs are only
        # listed when that SyncType is passed explicitly.
        page = ssm.list_resource_data_sync(SyncType="SyncFromSource", **kwargs)
        for item in page.get("ResourceDataSyncItems", []):
            if item["SyncName"] == sync_name:
                return item
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


def _poll_for_sync(ssm, sync_name: str, attempts: int = 40, delay: float = 3.0):
    """ListResourceDataSync is eventually consistent with respect to a preceding
    Create call; poll until the sync appears."""
    item = _find_sync(ssm, sync_name)
    for _ in range(attempts):
        if item is not None:
            return item
        time.sleep(delay)
        item = _find_sync(ssm, sync_name)
    return item


def _poll_for_absence(ssm, sync_name: str, attempts: int = 40, delay: float = 3.0):
    item = _find_sync(ssm, sync_name)
    for _ in range(attempts):
        if item is None:
            return None
        time.sleep(delay)
        item = _find_sync(ssm, sync_name)
    return item


def _delete_if_present(ssm, sync_name: str) -> None:
    try:
        ssm.delete_resource_data_sync(SyncName=sync_name, SyncType="SyncFromSource")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceDataSyncNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
