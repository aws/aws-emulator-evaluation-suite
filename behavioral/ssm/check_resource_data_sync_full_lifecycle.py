"""resource-data-sync-full-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-data-sync-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResourceDataSync registers a sync listed via ListResourceDataSync, editable
    via Update, and removable via Delete."""
    ssm = ctx.client("ssm")
    sync_name = ctx.unique_name("sim2real-rds-")

    ssm.create_resource_data_sync(
        SyncName=sync_name,
        SyncType="SyncFromSource",
        SyncSource={
            "SourceType": "SingleAccountMultiRegions",
            "SourceRegions": [ctx.region],
            "IncludeFutureRegions": False,
        },
    )
    ctx.on_cleanup(lambda: _delete_sync_if_exists(ssm, sync_name))

    item = _poll_for_sync(ssm, sync_name, lambda i: True, attempts=40, delay=3.0)
    assert item is not None, "created resource data sync not visible in ListResourceDataSync"
    assert item["SyncType"] == "SyncFromSource", f"expected SyncFromSource, got {item['SyncType']}"
    assert item["SyncSource"]["IncludeFutureRegions"] is False, (
        f"expected IncludeFutureRegions False at creation, got {item['SyncSource']['IncludeFutureRegions']}"
    )

    ssm.update_resource_data_sync(
        SyncName=sync_name,
        SyncType="SyncFromSource",
        SyncSource={
            "SourceType": "SingleAccountMultiRegions",
            "SourceRegions": [ctx.region],
            "IncludeFutureRegions": True,
        },
    )
    item = _poll_for_sync(ssm, sync_name, lambda i: i["SyncSource"]["IncludeFutureRegions"] is True, attempts=40, delay=3.0)
    assert item is not None, "updated resource data sync not visible in ListResourceDataSync"
    assert item["SyncSource"]["IncludeFutureRegions"] is True, (
        f"expected IncludeFutureRegions True after update, got {item['SyncSource']['IncludeFutureRegions']}"
    )

    ssm.delete_resource_data_sync(SyncName=sync_name, SyncType="SyncFromSource")
    item = _poll_for_absence(ssm, sync_name, attempts=40, delay=3.0)
    assert item is None, "resource data sync still visible after DeleteResourceDataSync"

    try:
        ssm.update_resource_data_sync(
            SyncName=sync_name,
            SyncType="SyncFromSource",
            SyncSource={
                "SourceType": "SingleAccountMultiRegions",
                "SourceRegions": [ctx.region],
                "IncludeFutureRegions": True,
            },
        )
        raise AssertionError("update_resource_data_sync succeeded against a deleted sync")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceDataSyncNotFoundException", (
            f"expected ResourceDataSyncNotFoundException for update on a deleted sync, got {code}"
        )
        assert message == (
            f"ResourceDataSync with name {sync_name} synctype SyncFromSource does not exists"
        ), f"unexpected message {message!r}"


def _find_sync(ssm, sync_name: str):
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        # ListResourceDataSync's SyncType parameter defaults to the legacy
        # "SyncToDestination" (S3) sync type; a sync created with SyncType
        # "SyncFromSource" (as this check does) is only returned when that
        # SyncType is passed explicitly.
        page = ssm.list_resource_data_sync(SyncType="SyncFromSource", **kwargs)
        for item in page.get("ResourceDataSyncItems", []):
            if item["SyncName"] == sync_name:
                return item
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


def _poll_for_sync(ssm, sync_name: str, predicate, attempts: int = 15, delay: float = 2.0):
    """ListResourceDataSync is eventually consistent with respect to a preceding
    Create/Update call; poll until the sync appears and satisfies predicate."""
    item = None
    for _ in range(attempts):
        item = _find_sync(ssm, sync_name)
        if item is not None and predicate(item):
            return item
        time.sleep(delay)
    return item


def _poll_for_absence(ssm, sync_name: str, attempts: int = 15, delay: float = 2.0):
    item = _find_sync(ssm, sync_name)
    for _ in range(attempts):
        if item is None:
            return None
        time.sleep(delay)
        item = _find_sync(ssm, sync_name)
    return item


def _delete_sync_if_exists(ssm, sync_name: str) -> None:
    try:
        # DeleteResourceDataSync, like ListResourceDataSync, defaults SyncType to the
        # legacy "SyncToDestination"; a sync created as "SyncFromSource" (as this check
        # does) is only found for deletion when that SyncType is passed explicitly,
        # otherwise it 404s with ResourceDataSyncNotFoundException.
        ssm.delete_resource_data_sync(SyncName=sync_name, SyncType="SyncFromSource")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceDataSyncNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
