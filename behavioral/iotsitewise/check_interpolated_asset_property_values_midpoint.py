"""interpolated-asset-property-values-midpoint."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "interpolated-asset-property-values-midpoint"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetInterpolatedAssetPropertyValues linearly interpolates between two ingested GOOD-quality points."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Level")
    asset_id = _create_asset(ctx, model_id)

    t0 = int(time.time()) - 300
    t1 = t0 + 120
    mid = t0 + 60
    entries = [{
        "entryId": "start",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 10.0}, "timestamp": {"timeInSeconds": t0}, "quality": "GOOD"}],
    }, {
        "entryId": "end",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 30.0}, "timestamp": {"timeInSeconds": t1}, "quality": "GOOD"}],
    }]
    put_resp = sw.batch_put_asset_property_value(entries=entries)
    assert put_resp["errorEntries"] == [], put_resp["errorEntries"]
    _poll_history(ctx, asset_id, property_id, t0 - 5, t1 + 5, expected_count=2)

    point = _poll_interpolated(ctx, asset_id, property_id, mid, window_s=t1 - t0)
    value = point["value"]["doubleValue"]
    assert abs(value - 20.0) < 1.0, f"expected interpolated midpoint ~20.0 at t={mid}, got {value}"


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
        tags={"sim2real-behav": "interpolated-asset-property-values-midpoint"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    described = sw.describe_asset_model(assetModelId=model_id)
    prop = next(p for p in described["assetModelProperties"] if p["name"] == prop_name)
    return model_id, prop["id"]


def _create_asset(ctx, model_id, name=None):
    sw = ctx.client("iotsitewise")
    asset_name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(
        assetName=asset_name, assetModelId=model_id,
        tags={"sim2real-behav": "interpolated-asset-property-values-midpoint"},
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _poll_history(ctx, asset_id, property_id, start_s, end_s, expected_count, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    start = datetime.fromtimestamp(start_s, tz=timezone.utc)
    end = datetime.fromtimestamp(end_s, tz=timezone.utc)
    deadline = time.monotonic() + timeout_s
    items = []
    while time.monotonic() < deadline:
        resp = sw.get_asset_property_value_history(
            assetId=asset_id, propertyId=property_id,
            startDate=start, endDate=end, timeOrdering="ASCENDING",
        )
        items = resp["assetPropertyValueHistory"]
        if len(items) >= expected_count:
            return items
        time.sleep(interval_s)
    raise AssertionError(f"expected {expected_count} history items, got {len(items)}")


def _poll_interpolated(ctx, asset_id, property_id, at_second, window_s, timeout_s=90.0, interval_s=5.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    values = []
    while time.monotonic() < deadline:
        resp = sw.get_interpolated_asset_property_values(
            assetId=asset_id, propertyId=property_id,
            startTimeInSeconds=at_second, endTimeInSeconds=at_second + 1,
            quality="GOOD", intervalInSeconds=1, type="LINEAR_INTERPOLATION",
            intervalWindowInSeconds=window_s,
        )
        values = resp["interpolatedAssetPropertyValues"]
        match = next((v for v in values if v["timestamp"]["timeInSeconds"] == at_second), None)
        if match is not None:
            return match
        time.sleep(interval_s)
    raise AssertionError(f"no interpolated value at t={at_second} after {timeout_s}s (last response: {values})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
