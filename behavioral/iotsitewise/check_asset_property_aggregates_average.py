"""asset-property-aggregates-average."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asset-property-aggregates-average"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAssetPropertyAggregates computes the correct AVERAGE for two values ingested into the same 1-minute resolution bucket."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Load")
    asset_id = _create_asset(ctx, model_id)

    minute_start = (int(time.time()) // 60 - 3) * 60  # a full minute, safely in the past
    t1, t2 = minute_start + 5, minute_start + 35
    v1, v2 = 10.0, 30.0
    entries = [{
        "entryId": "e1",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": v1}, "timestamp": {"timeInSeconds": t1}, "quality": "GOOD"}],
    }, {
        "entryId": "e2",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": v2}, "timestamp": {"timeInSeconds": t2}, "quality": "GOOD"}],
    }]
    put_resp = sw.batch_put_asset_property_value(entries=entries)
    assert put_resp["errorEntries"] == [], f"expected no ingestion errors, got {put_resp['errorEntries']}"

    aggregated = _poll_aggregates(ctx, asset_id, property_id, minute_start, minute_start + 60)
    # GetAssetPropertyAggregates stamps a 1m bucket with the timestamp of the bucket's END
    # (minute_start + 60), not its start.
    bucket_end = minute_start + 60
    got_bucket = int(aggregated["timestamp"].timestamp())
    assert got_bucket == bucket_end, f"expected aggregate bucket timestamp {bucket_end}, got {got_bucket}"
    expected_avg = (v1 + v2) / 2
    got_avg = aggregated["value"]["average"]
    assert abs(got_avg - expected_avg) < 0.01, f"expected AVERAGE {expected_avg}, got {got_avg}"


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
        tags={"sim2real": CHECK},
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
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id, tags={"sim2real": CHECK})
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _poll_aggregates(ctx, asset_id, property_id, start_s, end_s, timeout_s=90.0, interval_s=5.0):
    sw = ctx.client("iotsitewise")
    start = datetime.fromtimestamp(start_s, tz=timezone.utc)
    end = datetime.fromtimestamp(end_s, tz=timezone.utc)
    deadline = time.monotonic() + timeout_s
    values = []
    while time.monotonic() < deadline:
        resp = sw.get_asset_property_aggregates(
            assetId=asset_id, propertyId=property_id,
            aggregateTypes=["AVERAGE"], resolution="1m",
            startDate=start, endDate=end,
        )
        values = resp["aggregatedValues"]
        if values:
            return values[0]
        time.sleep(interval_s)
    raise AssertionError(f"no aggregated values appeared for window [{start_s},{end_s}) after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
