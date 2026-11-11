"""get-interpolated-asset-property-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-interpolated-asset-property-values"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetInterpolatedAssetPropertyValues linearly interpolates a midpoint value between two raw,
    ingested data points."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)
    asset_id = _create_asset(ctx, client, model_id)

    t0 = int(time.time()) - 120  # safely in the past
    entries = [{
        "entryId": "e1",
        "assetId": asset_id,
        "propertyId": prop_id,
        "propertyValues": [
            {"value": {"doubleValue": 0.0}, "timestamp": {"timeInSeconds": t0, "offsetInNanos": 0}, "quality": "GOOD"},
            {"value": {"doubleValue": 100.0}, "timestamp": {"timeInSeconds": t0 + 60, "offsetInNanos": 0}, "quality": "GOOD"},
        ],
    }]
    resp = client.batch_put_asset_property_value(entries=entries)
    assert resp["errorEntries"] == [], resp["errorEntries"]

    points = _poll_interpolated(client, asset_id, prop_id, t0, t0 + 60)
    by_time = {p["timestamp"]["timeInSeconds"]: p["value"]["doubleValue"] for p in points}
    assert by_time.get(t0) == 0.0, by_time
    assert by_time.get(t0 + 60) == 100.0, by_time
    mid = by_time.get(t0 + 30)
    assert mid is not None and abs(mid - 50.0) < 1e-6, by_time


def _poll_interpolated(client, asset_id, prop_id, start_s, end_s, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_interpolated_asset_property_values(
            assetId=asset_id, propertyId=prop_id,
            startTimeInSeconds=start_s, endTimeInSeconds=end_s,
            quality="GOOD", intervalInSeconds=30, type="LINEAR_INTERPOLATION",
        )
        if len(resp["interpolatedAssetPropertyValues"]) >= 3:
            return resp["interpolatedAssetPropertyValues"]
        time.sleep(interval_s)
    raise AssertionError("interpolated values never appeared")


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
        tags={"sim2real-behav-owner": "check_get_interpolated_asset_property_values"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(
        assetName=name, assetModelId=model_id,
        tags={"sim2real-behav-owner": "check_get_interpolated_asset_property_values"},
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset(assetId=asset_id)))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
