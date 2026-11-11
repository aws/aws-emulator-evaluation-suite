"""associate-assets-concurrent-duplicate-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-assets-concurrent-duplicate-race"
GROUP = "concurrency"
SERVICES = ["iotsitewise"]

_IN_PROGRESS_MESSAGE = "A hierarchy with ID {hierarchy} already exists"
_DUPLICATE_CODE = "InvalidRequestException"
_DUPLICATE_MESSAGE = "Child asset already has a parent"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent AssociateAssets calls for one parent/hierarchy/child associate the child once:
    exactly one succeeds, any other is refused with the in-progress ConflictingOperationException or
    the sequential-duplicate error and its exact message, and a later duplicate gets the latter."""
    sw = ctx.client("iotsitewise")
    parent_model_id, child_model_id, hierarchy_id = _create_hierarchy(ctx)
    parent_asset_id = _create_asset(ctx, parent_model_id)
    child_asset_id = _create_asset(ctx, child_model_id)
    ctx.on_cleanup(lambda: _disassociate_best_effort(ctx, parent_asset_id, hierarchy_id, child_asset_id))

    racers = 6

    def _associate(_i):
        try:
            sw.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
            return ("ok", None)
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        results = list(pool.map(_associate, range(racers)))

    successes = [r for r in results if r == ("ok", None)]
    failures = [r for r in results if r != ("ok", None)]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)} (results={results})"
    in_progress = ("ConflictingOperationException", _IN_PROGRESS_MESSAGE.format(hierarchy=hierarchy_id))
    duplicate = (_DUPLICATE_CODE, _DUPLICATE_MESSAGE)
    # An overlapping racer hits the in-progress association; a serialized one is a duplicate.
    assert all(error in (in_progress, duplicate) for error in failures), (
        f"a losing racer must get {in_progress} or {duplicate}, got {failures}"
    )

    children = _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids={child_asset_id})
    assert len(children) == 1

    repeat = _associate(0)
    assert repeat == duplicate, f"expected a sequential duplicate association refused with {duplicate}, got {repeat}"


def _delete_asset_model_best_effort(ctx, model_id, timeout_s=120.0, interval_s=3.0):
    """Delete the model and wait until it is gone, since a parent model must go before its child."""
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sw.describe_asset_model(assetModelId=model_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset model {model_id} still exists {timeout_s}s after DeleteAssetModel")


def _delete_asset_best_effort(ctx, asset_id, timeout_s=120.0, interval_s=3.0):
    """Delete the asset and wait until it is gone, since its model cannot be deleted before."""
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset(assetId=asset_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sw.describe_asset(assetId=asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} still exists {timeout_s}s after DeleteAsset")


def _disassociate_best_effort(ctx, parent_asset_id, hierarchy_id, child_asset_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.disassociate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_asset_model_active(ctx, model_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    state = None
    described = None
    while time.monotonic() < deadline:
        described = sw.describe_asset_model(assetModelId=model_id)
        state = described["assetModelStatus"]["state"]
        if state == "ACTIVE":
            return described
        if state == "FAILED":
            raise AssertionError(
                f"asset model {model_id} entered FAILED: {described['assetModelStatus'].get('error')}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"asset model {model_id} did not reach ACTIVE within {timeout_s}s (last={state})")


def _wait_asset_active(ctx, asset_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    state = None
    described = None
    while time.monotonic() < deadline:
        described = sw.describe_asset(assetId=asset_id)
        state = described["assetStatus"]["state"]
        if state == "ACTIVE":
            return described
        if state == "FAILED":
            raise AssertionError(f"asset {asset_id} entered FAILED: {described['assetStatus'].get('error')}")
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} did not reach ACTIVE within {timeout_s}s (last={state})")


def _create_asset(ctx, model_id, name=None):
    sw = ctx.client("iotsitewise")
    asset_name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id)
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _create_hierarchy(ctx, hierarchy_name="Children"):
    sw = ctx.client("iotsitewise")
    child_model_name = ctx.unique_name("sim2real-behav-childmodel-")
    child_resp = sw.create_asset_model(assetModelName=child_model_name)
    child_model_id = child_resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, child_model_id))
    _wait_asset_model_active(ctx, child_model_id)

    parent_model_name = ctx.unique_name("sim2real-behav-parentmodel-")
    parent_resp = sw.create_asset_model(
        assetModelName=parent_model_name,
        assetModelHierarchies=[{"name": hierarchy_name, "childAssetModelId": child_model_id}],
    )
    parent_model_id = parent_resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, parent_model_id))
    described_parent = _wait_asset_model_active(ctx, parent_model_id)
    hierarchy_id = next(h["id"] for h in described_parent["assetModelHierarchies"] if h["name"] == hierarchy_name)
    return parent_model_id, child_model_id, hierarchy_id


def _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    children = []
    while time.monotonic() < deadline:
        resp = sw.list_associated_assets(
            assetId=parent_asset_id, hierarchyId=hierarchy_id, traversalDirection="CHILD"
        )
        children = resp["assetSummaries"]
        if {c["id"] for c in children} == expected_ids:
            return children
        time.sleep(interval_s)
    raise AssertionError(f"children {expected_ids} never appeared under hierarchy {hierarchy_id} (last={children})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
