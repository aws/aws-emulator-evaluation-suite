"""disassociate-assets-never-associated-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-assets-never-associated-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateAssets on a (parent, hierarchy, child) triple that was never associated is
    rejected with ResourceNotFoundException and changes nothing; associating the triple first
    (positive control) lets the identical disassociate call succeed."""
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

    code, message = _error(
        lambda: sw.disassociate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=child_id)
    )
    assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    expected_message = f"A hierarchy with ID {hierarchy_id} doesn't exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the child is (still) not associated to the parent.
    associated_ids = [a["id"] for a in sw.list_associated_assets(assetId=parent_id, hierarchyId=hierarchy_id)["assetSummaries"]]
    assert child_id not in associated_ids, f"child {child_id} unexpectedly associated: {associated_ids}"

    # Positive control: associate first, then the identical disassociate call succeeds.
    sw.associate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=child_id)
    _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_id, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: child_id in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )
    sw.disassociate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=child_id)
    final_ids = _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_id, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: child_id not in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert child_id not in final_ids, f"child {child_id} still associated after disassociate: {final_ids}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


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
