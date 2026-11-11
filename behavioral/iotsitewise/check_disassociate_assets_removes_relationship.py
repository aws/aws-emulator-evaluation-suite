"""disassociate-assets-removes-relationship."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-assets-removes-relationship"
GROUP = "state"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateAssets removes a previously associated child from the parent's hierarchy listing."""
    sw = ctx.client("iotsitewise")
    parent_model_id, child_model_id, hierarchy_id = _create_hierarchy(ctx)
    parent_asset_id = _create_asset(ctx, parent_model_id)
    child_asset_id = _create_asset(ctx, child_model_id)

    sw.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
    _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids={child_asset_id})

    sw.disassociate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)

    remaining = _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids=set())
    assert remaining == [], f"expected no associated children after disassociate, got {remaining}"


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_asset_best_effort(ctx, asset_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset(assetId=asset_id)
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
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id, tags={"sim2real": "true"})
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _create_hierarchy(ctx, hierarchy_name="Children"):
    sw = ctx.client("iotsitewise")
    child_model_name = ctx.unique_name("sim2real-behav-childmodel-")
    child_resp = sw.create_asset_model(assetModelName=child_model_name, tags={"sim2real": "true"})
    child_model_id = child_resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, child_model_id))
    _wait_asset_model_active(ctx, child_model_id)

    parent_model_name = ctx.unique_name("sim2real-behav-parentmodel-")
    parent_resp = sw.create_asset_model(
        assetModelName=parent_model_name,
        assetModelHierarchies=[{"name": hierarchy_name, "childAssetModelId": child_model_id}],
        tags={"sim2real": "true"},
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
