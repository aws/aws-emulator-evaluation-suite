"""asset-property-value-history-ordering."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asset-property-value-history-ordering"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Values ingested at increasing timestamps come back from GetAssetPropertyValueHistory in ascending time order with correct values."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Speed")
    asset_id = _create_asset(ctx, model_id)

    base = int(time.time()) - 120
    timestamps = [base, base + 5, base + 10]
    values = [1.0, 2.0, 3.0]
    # Submit out of chronological order: entry-0 carries the *last* timestamp, entry-2
    # the *first*. If GetAssetPropertyValueHistory merely echoed ingestion order, this
    # would fail; asserting ascending timestamp order below proves it actually sorts.
    submit_order = [2, 0, 1]
    entries = [{
        "entryId": f"entry-{i}",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{
            "value": {"doubleValue": values[idx]},
            "timestamp": {"timeInSeconds": timestamps[idx]},
            "quality": "GOOD",
        }],
    } for i, idx in enumerate(submit_order)]
    put_resp = sw.batch_put_asset_property_value(entries=entries)
    assert put_resp["errorEntries"] == []

    history = _poll_history(ctx, asset_id, property_id, base - 5, base + 15, expected_count=3)
    assert [h["timestamp"]["timeInSeconds"] for h in history] == timestamps
    assert [h["value"]["doubleValue"] for h in history] == values


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


def _create_asset(ctx, model_id, name=None):
    sw = ctx.client("iotsitewise")
    asset_name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
