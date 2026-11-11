"""batch-put-timestamp-out-of-range-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-timestamp-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A timestamp more than 10 minutes in the future is rejected per-entry with TimestampOutOfRangeException, is never stored, and a current timestamp still ingests fine."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Torque")
    asset_id = _create_asset(ctx, model_id)

    future_ts = int(time.time()) + 20 * 60  # 20 minutes in the future; AWS allows at most 10
    resp = sw.batch_put_asset_property_value(entries=[{
        "entryId": "future",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 99.0}, "timestamp": {"timeInSeconds": future_ts}, "quality": "GOOD"}],
    }])
    assert len(resp["errorEntries"]) == 1, f"expected exactly 1 errorEntries for the future-timestamp entry, got {resp['errorEntries']}"
    error_entry = resp["errorEntries"][0]
    assert error_entry["entryId"] == "future", f"expected the errorEntry to reference entryId 'future', got {error_entry['entryId']}"
    assert error_entry["errors"][0]["errorCode"] == "TimestampOutOfRangeException", f"expected errorCode TimestampOutOfRangeException, got {error_entry['errors'][0]['errorCode']}"

    # effect absent: nothing was ever stored at that future timestamp
    start = datetime.fromtimestamp(future_ts - 5, tz=timezone.utc)
    end = datetime.fromtimestamp(future_ts + 5, tz=timezone.utc)
    history = sw.get_asset_property_value_history(assetId=asset_id, propertyId=property_id, startDate=start, endDate=end)
    assert history["assetPropertyValueHistory"] == [], f"expected no stored history around the rejected future timestamp, got {history['assetPropertyValueHistory']}"

    # positive control: a value at a valid (current) timestamp still ingests
    now_ts = int(time.time()) - 5
    control = sw.batch_put_asset_property_value(entries=[{
        "entryId": "control",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 5.0}, "timestamp": {"timeInSeconds": now_ts}, "quality": "GOOD"}],
    }])
    assert control["errorEntries"] == [], f"expected the valid current-timestamp entry to ingest with no errors, got {control['errorEntries']}"
    _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp=now_ts)


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


def _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sw.get_asset_property_value(assetId=asset_id, propertyId=property_id)
            value = resp.get("propertyValue")
            if value is not None:
                last = value
                if last["timestamp"]["timeInSeconds"] == expect_timestamp:
                    return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"asset property value with timestamp {expect_timestamp} never appeared (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
