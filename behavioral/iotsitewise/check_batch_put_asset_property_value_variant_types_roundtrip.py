"""batch-put-asset-property-value-variant-types-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-asset-property-value-variant-types-roundtrip"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """STRING and BOOLEAN asset property values round-trip through BatchPutAssetPropertyValue and
    GetAssetPropertyValue with their exact Variant type preserved (not silently coerced to a string)."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[
            {"name": "Mode", "dataType": "STRING", "type": {"measurement": {}}},
            {"name": "Running", "dataType": "BOOLEAN", "type": {"measurement": {}}},
        ],
    )
    asset_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-asset-"), model_id)
    mode_id = _property_id_by_name(sw, asset_id, "Mode")
    running_id = _property_id_by_name(sw, asset_id, "Running")

    now_seconds = int(time.time())
    put_resp = sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "mode",
                "assetId": asset_id,
                "propertyId": mode_id,
                "propertyValues": [
                    {"value": {"stringValue": "AUTO"}, "timestamp": {"timeInSeconds": now_seconds}, "quality": "GOOD"}
                ],
            },
            {
                "entryId": "running",
                "assetId": asset_id,
                "propertyId": running_id,
                "propertyValues": [
                    {"value": {"booleanValue": True}, "timestamp": {"timeInSeconds": now_seconds}, "quality": "GOOD"}
                ],
            },
        ]
    )
    assert put_resp["errorEntries"] == [], f"expected no error entries, got {put_resp['errorEntries']!r}"

    mode_value = _poll_until(
        lambda: sw.get_asset_property_value(assetId=asset_id, propertyId=mode_id),
        lambda r: "propertyValue" in r,
        timeout_s=60.0,
        interval_s=2.0,
    )["propertyValue"]
    assert mode_value["value"] == {"stringValue": "AUTO"}, (
        f"expected STRING variant {{'stringValue': 'AUTO'}} to round-trip unchanged, got {mode_value['value']!r}"
    )

    running_value = _poll_until(
        lambda: sw.get_asset_property_value(assetId=asset_id, propertyId=running_id),
        lambda r: "propertyValue" in r,
        timeout_s=60.0,
        interval_s=2.0,
    )["propertyValue"]
    assert running_value["value"] == {"booleanValue": True}, (
        f"expected BOOLEAN variant {{'booleanValue': True}} to round-trip unchanged, got {running_value['value']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last = None
        if last is not None and predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {
        "assetModelName": name,
        "assetModelProperties": properties,
        "tags": {"sim2real-behav-check": CHECK},
    }
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
    resp = sw.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real-behav-check": CHECK})
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


def _property_id_by_name(sw, asset_id, prop_name):
    props = sw.describe_asset(assetId=asset_id)["assetProperties"]
    for p in props:
        if p["name"] == prop_name:
            return p["id"]
    raise AssertionError(f"property {prop_name!r} not found on asset {asset_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
