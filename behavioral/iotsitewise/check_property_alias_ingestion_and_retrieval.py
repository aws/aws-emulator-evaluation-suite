"""property-alias-ingestion-and-retrieval."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "property-alias-ingestion-and-retrieval"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Setting a property alias via UpdateAssetProperty lets BatchPutAssetPropertyValue and
    GetAssetPropertyValue address the same asset property purely by alias."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)
    asset_id = _create_asset(ctx, client, model_id)

    alias = ctx.unique_name("/sim2real/behav/prop-")
    client.update_asset_property(assetId=asset_id, propertyId=prop_id, propertyAlias=alias)

    described = client.describe_asset_property(assetId=asset_id, propertyId=prop_id)
    assert described["assetProperty"]["alias"] == alias, (
        f"expected alias {alias!r}, got {described['assetProperty'].get('alias')!r}"
    )

    now = int(time.time())
    resp = client.batch_put_asset_property_value(entries=[{
        "entryId": "e1",
        "propertyAlias": alias,
        "propertyValues": [
            {"value": {"doubleValue": 12.5}, "timestamp": {"timeInSeconds": now, "offsetInNanos": 0}, "quality": "GOOD"}
        ],
    }])
    assert resp["errorEntries"] == [], resp["errorEntries"]

    value = _poll_value_by_alias(client, alias, expected=12.5)
    assert value == 12.5, f"expected 12.5 by alias, got {value}"

    # the same underlying value is also visible by assetId/propertyId
    by_id = client.get_asset_property_value(assetId=asset_id, propertyId=prop_id)
    by_id_value = by_id["propertyValue"]["value"]["doubleValue"]
    assert by_id_value == 12.5, f"expected 12.5 by assetId/propertyId, got {by_id_value}"


def _poll_value_by_alias(client, alias, expected, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = client.get_asset_property_value(propertyAlias=alias)
            v = resp["propertyValue"]["value"].get("doubleValue")
            if v == expected:
                return v
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError("value never appeared for alias")


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


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": CHECK})
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset(assetId=asset_id)))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
