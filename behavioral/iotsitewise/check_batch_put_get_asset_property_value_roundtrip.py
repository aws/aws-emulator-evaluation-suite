"""batch-put-get-asset-property-value-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-get-asset-property-value-roundtrip"
GROUP = "e2e"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A child asset associated under a parent is the only asset ListAssociatedAssets returns, and a value
    ingested on it with BatchPutAssetPropertyValue reads back as 42.5 with the same timestamp and quality GOOD."""
    sw = ctx.client("iotsitewise")
    child_model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Pressure")
    parent_model_id = _create_asset_model_with_hierarchy(ctx, child_model_id)
    hierarchy_id = sw.describe_asset_model(assetModelId=parent_model_id)["assetModelHierarchies"][0]["id"]

    parent_id = _create_asset(ctx, parent_model_id, name=ctx.unique_name("sim2real-behav-parent-"))
    asset_id = _create_asset(ctx, child_model_id, name=ctx.unique_name("sim2real-behav-child-"))

    sw.associate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=asset_id)
    associated_ids = _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_id, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: asset_id in ids,
    )
    assert associated_ids == [asset_id], f"expected only {asset_id} associated under {hierarchy_id}, got {associated_ids}"

    ts = int(time.time()) - 30
    put_resp = sw.batch_put_asset_property_value(entries=[{
        "entryId": "entry-1",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{
            "value": {"doubleValue": 42.5},
            "timestamp": {"timeInSeconds": ts},
            "quality": "GOOD",
        }],
    }])
    assert put_resp["errorEntries"] == [], f"expected no errorEntries, got {put_resp['errorEntries']}"

    value = _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp=ts)
    assert value["value"]["doubleValue"] == 42.5, f"expected doubleValue 42.5, got {value['value']}"
    assert value["timestamp"]["timeInSeconds"] == ts, f"expected timestamp {ts}, got {value['timestamp']}"
    assert value["quality"] == "GOOD", f"expected quality GOOD, got {value['quality']}"

    # tear the graph back down, verifying deletion at each step before proceeding
    sw.disassociate_assets(assetId=parent_id, hierarchyId=hierarchy_id, childAssetId=asset_id)
    _poll_until(
        lambda: [a["id"] for a in sw.list_associated_assets(assetId=parent_id, hierarchyId=hierarchy_id)["assetSummaries"]],
        lambda ids: asset_id not in ids,
    )

    sw.delete_asset(assetId=asset_id)
    _poll_asset_gone(sw, asset_id)
    sw.delete_asset(assetId=parent_id)
    _poll_asset_gone(sw, parent_id)

    sw.delete_asset_model(assetModelId=parent_model_id)
    _poll_model_gone(sw, parent_model_id)
    sw.delete_asset_model(assetModelId=child_model_id)
    _poll_model_gone(sw, child_model_id)


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


def _create_asset_model_with_measurement(ctx, prop_name="Value", data_type="DOUBLE"):
    sw = ctx.client("iotsitewise")
    model_name = ctx.unique_name("sim2real-behav-model-")
    resp = sw.create_asset_model(
        assetModelName=model_name,
        assetModelProperties=[{
            "name": prop_name,
            "dataType": data_type,
            "type": {"measurement": {}},
        }],
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    described = sw.describe_asset_model(assetModelId=model_id)
    prop = next(p for p in described["assetModelProperties"] if p["name"] == prop_name)
    return model_id, prop["id"]


def _create_asset_model_with_hierarchy(ctx, child_model_id):
    sw = ctx.client("iotsitewise")
    model_name = ctx.unique_name("sim2real-behav-parentmodel-")
    resp = sw.create_asset_model(
        assetModelName=model_name,
        assetModelHierarchies=[{"name": "Children", "childAssetModelId": child_model_id}],
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    return model_id


def _create_asset(ctx, model_id, name=None):
    sw = ctx.client("iotsitewise")
    asset_name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id)
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sw.get_asset_property_value(assetId=asset_id, propertyId=property_id)
            last = resp["propertyValue"]
            if last["timestamp"]["timeInSeconds"] == expect_timestamp:
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"asset property value with timestamp {expect_timestamp} never appeared (last={last})")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_asset_gone(sw, asset_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sw.describe_asset(assetId=asset_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} was never deleted")


def _poll_model_gone(sw, model_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sw.describe_asset_model(assetModelId=model_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset model {model_id} was never deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

