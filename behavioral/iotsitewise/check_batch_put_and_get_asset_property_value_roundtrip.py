"""batch-put-and-get-asset-property-value-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-and-get-asset-property-value-roundtrip"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A value ingested via BatchPutAssetPropertyValue is retrievable via GetAssetPropertyValue with matching value/quality/timestamp."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[{"name": "Temperature", "dataType": "DOUBLE", "type": {"measurement": {}}}],
    )
    asset_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-asset-"), model_id)
    property_id = _property_id_by_name(sw, asset_id, "Temperature")

    now_seconds = int(time.time())
    put_resp = sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "e1",
                "assetId": asset_id,
                "propertyId": property_id,
                "propertyValues": [
                    {
                        "value": {"doubleValue": 72.5},
                        "timestamp": {"timeInSeconds": now_seconds},
                        "quality": "GOOD",
                    }
                ],
            }
        ]
    )
    assert put_resp["errorEntries"] == [], f"expected no errorEntries, got {put_resp['errorEntries']!r}"

    result = _poll_until(
        lambda: sw.get_asset_property_value(assetId=asset_id, propertyId=property_id),
        lambda r: "propertyValue" in r,
        timeout_s=60.0,
        interval_s=2.0,
    )
    value = result["propertyValue"]
    assert value["value"]["doubleValue"] == 72.5, f"expected doubleValue=72.5, got {value['value']!r}"
    assert value["quality"] == "GOOD", f"expected quality=GOOD, got {value['quality']!r}"
    assert value["timestamp"]["timeInSeconds"] == now_seconds, (
        f"expected timeInSeconds={now_seconds}, got {value['timestamp']!r}"
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
    kwargs = {"assetModelName": name, "assetModelProperties": properties, "tags": {"sim2real": CHECK}}
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
    resp = sw.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": CHECK})
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
