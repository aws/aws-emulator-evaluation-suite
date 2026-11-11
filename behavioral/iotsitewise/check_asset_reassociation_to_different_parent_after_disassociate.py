"""asset-reassociation-to-different-parent-after-disassociate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-reassociation-to-different-parent-after-disassociate"
GROUP = "hierarchy"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DisassociateAssets fully releases a child from parent A, the SAME child can be
    associated under a DIFFERENT parent B of the same hierarchy type, and the child then shows up
    ONLY under B, never simultaneously under both."""
    sw = ctx.client("iotsitewise")

    child_model_id = _create_asset_model_active(ctx, sw, ctx.unique_name("sim2real-sw-childmodel-"), properties=[])
    parent_model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-parentmodel-"),
        properties=[],
        hierarchies=[{"name": "Children", "childAssetModelId": child_model_id}],
    )
    hierarchy_id = sw.describe_asset_model(assetModelId=parent_model_id)["assetModelHierarchies"][0]["id"]

    parent_a = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-parent-a-"), parent_model_id)
    parent_b = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-parent-b-"), parent_model_id)
    child_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-child-"), child_model_id)

    sw.associate_assets(assetId=parent_a, hierarchyId=hierarchy_id, childAssetId=child_id)
    _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_a, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: child_id in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )

    sw.disassociate_assets(assetId=parent_a, hierarchyId=hierarchy_id, childAssetId=child_id)
    _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_a, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: child_id not in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )

    sw.associate_assets(assetId=parent_b, hierarchyId=hierarchy_id, childAssetId=child_id)

    def _cleanup_final_association():
        try:
            sw.disassociate_assets(assetId=parent_b, hierarchyId=hierarchy_id, childAssetId=child_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_final_association)

    ids_under_b = _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_b, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: child_id in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert ids_under_b == [child_id], f"expected only [{child_id}] under parent_b, got {ids_under_b}"

    ids_under_a = [a["id"] for a in sw.list_associated_assets(assetId=parent_a, hierarchyId=hierarchy_id)["assetSummaries"]]
    assert child_id not in ids_under_a, "child must not remain associated to the original parent"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {"assetModelName": name, "assetModelProperties": properties, "tags": {"sim2real": "true"}}
    if hierarchies:
        kwargs["assetModelHierarchies"] = hierarchies
    resp = sw.create_asset_model(**kwargs)
    model_id = resp["assetModelId"]

    def _cleanup():
        try:
            sw.delete_asset_model(assetModelId=model_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    state = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id)["assetModelStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=3.0,
    )
    if state != "ACTIVE":
        raise AssertionError(f"asset model did not become ACTIVE (state={state})")
    return model_id


def _create_asset_active(ctx, sw, name, model_id, timeout_s=120.0):
    resp = sw.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": "true"})
    asset_id = resp["assetId"]

    def _cleanup():
        try:
            sw.delete_asset(assetId=asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    state = _poll_until(
        lambda: sw.describe_asset(assetId=asset_id)["assetStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=3.0,
    )
    if state != "ACTIVE":
        raise AssertionError(f"asset did not become ACTIVE (state={state})")
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
