"""associate-assets-hierarchy-visible-in-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-assets-hierarchy-visible-in-list"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateAssets makes the child asset discoverable via ListAssociatedAssets under the
    parent's hierarchy, with matching asset-model metadata."""
    client = ctx.client("iotsitewise")
    child_model_id, _ = _create_measurement_model(ctx, client)
    parent_model_id, hierarchy_id = _create_model_with_hierarchy(ctx, client, child_model_id)
    parent_asset_id = _create_asset(ctx, client, parent_model_id)
    child_asset_id = _create_asset(ctx, client, child_model_id)
    ctx.on_cleanup(lambda: _safe(lambda: client.disassociate_assets(
        assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)))

    before = client.list_associated_assets(
        assetId=parent_asset_id, hierarchyId=hierarchy_id, traversalDirection="CHILD",
    )["assetSummaries"]
    assert not any(s["id"] == child_asset_id for s in before), (
        f"child {child_asset_id} already listed under hierarchy {hierarchy_id} before AssociateAssets: {before}"
    )

    client.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)

    summaries = _poll_associated_contains(client, parent_asset_id, hierarchy_id, child_asset_id)
    matching = next(s for s in summaries if s["id"] == child_asset_id)
    assert matching["assetModelId"] == child_model_id, (
        f"expected assetModelId={child_model_id} for child {child_asset_id} in ListAssociatedAssets, "
        f"got {matching['assetModelId']}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_model_active(client, model_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_asset_model(assetModelId=model_id)["assetModelStatus"]
        if status["state"] == "ACTIVE":
            return
        if status["state"] == "FAILED":
            raise AssertionError(f"asset model entered FAILED state: {status.get('error')}")
        time.sleep(interval_s)
    raise AssertionError("asset model never reached ACTIVE")


def _poll_asset_active(client, asset_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_asset(assetId=asset_id)["assetStatus"]
        if status["state"] == "ACTIVE":
            return
        if status["state"] == "FAILED":
            raise AssertionError(f"asset entered FAILED state: {status.get('error')}")
        time.sleep(interval_s)
    raise AssertionError("asset never reached ACTIVE")


def _poll_associated_contains(client, parent_asset_id, hierarchy_id, child_asset_id, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summaries = client.list_associated_assets(
            assetId=parent_asset_id, hierarchyId=hierarchy_id, traversalDirection="CHILD",
        )["assetSummaries"]
        if any(s["id"] == child_asset_id for s in summaries):
            return summaries
        time.sleep(interval_s)
    raise AssertionError("child was never visible in ListAssociatedAssets")


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real": "true"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_model_with_hierarchy(ctx, client, child_model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-parentmodel-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelHierarchies=[{"name": "ChildHierarchy", "childAssetModelId": child_model_id}],
        tags={"sim2real": "true"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    hierarchy_id = client.describe_asset_model(assetModelId=model_id)["assetModelHierarchies"][0]["id"]
    return model_id, hierarchy_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": "true"})
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset(assetId=asset_id)))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
