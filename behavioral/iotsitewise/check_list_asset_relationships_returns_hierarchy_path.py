"""list-asset-relationships-returns-hierarchy-path."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-asset-relationships-returns-hierarchy-path"
GROUP = "hierarchy"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After associating a child asset under a parent hierarchy, ListAssetRelationships(PATH_TO_ROOT)
    on the child reports the parent/child pair."""
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

    parent_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-parent-"), parent_model_id)
    child_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-child-"), child_model_id)

    sw.associate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=child_id)

    def _cleanup_assoc():
        try:
            sw.disassociate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=child_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_assoc)

    summaries = _poll_until(
        lambda: sw.list_asset_relationships(assetId=child_id, traversalType="PATH_TO_ROOT")["assetRelationshipSummaries"],
        lambda s: len(s) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    matches = [
        s for s in summaries
        if s.get("relationshipType") == "HIERARCHY"
        and s.get("hierarchyInfo", {}).get("parentAssetId") == parent_id
        and s.get("hierarchyInfo", {}).get("childAssetId") == child_id
    ]
    assert len(matches) == 1, summaries


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
    kwargs = {"assetModelName": name, "assetModelProperties": properties}
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
    resp = sw.create_asset(assetName=name, assetModelId=model_id)
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
