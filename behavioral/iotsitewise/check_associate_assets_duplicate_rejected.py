"""associate-assets-duplicate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-assets-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating the same child under the same hierarchy twice is rejected the second time, the child still appears exactly once, and associating a different child still succeeds."""
    sw = ctx.client("iotsitewise")
    parent_model_id, child_model_id, hierarchy_id = _create_hierarchy(ctx)
    parent_asset_id = _create_asset(ctx, parent_model_id)
    child_asset_id = _create_asset(ctx, child_model_id)
    other_child_asset_id = _create_asset(ctx, child_model_id)

    sw.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
    ctx.on_cleanup(lambda: _disassociate_best_effort(ctx, parent_asset_id, hierarchy_id, child_asset_id))
    _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids={child_asset_id})

    code, message = _error(lambda: sw.associate_assets(
        assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id
    ))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == "Child asset already has a parent", f"unexpected message: {message!r}"

    # effect absent: still only one association under the hierarchy, not two
    children = sw.list_associated_assets(
        assetId=parent_asset_id, hierarchyId=hierarchy_id, traversalDirection="CHILD"
    )["assetSummaries"]
    assert len(children) == 1, f"expected exactly one associated child, got {children}"
    assert children[0]["id"] == child_asset_id, f"expected {child_asset_id}, got {children[0]['id']}"

    # restore: disassociating then re-issuing the identical call succeeds again
    sw.disassociate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
    sw.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
    _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids={child_asset_id})

    # positive control: associating a genuinely different child still succeeds
    sw.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=other_child_asset_id)
    ctx.on_cleanup(lambda: _disassociate_best_effort(ctx, parent_asset_id, hierarchy_id, other_child_asset_id))
    _poll_associated_children(ctx, parent_asset_id, hierarchy_id, expected_ids={child_asset_id, other_child_asset_id})


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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
