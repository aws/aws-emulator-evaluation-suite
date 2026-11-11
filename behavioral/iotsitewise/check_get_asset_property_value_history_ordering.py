"""get-asset-property-value-history-ordering."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-asset-property-value-history-ordering"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAssetPropertyValueHistory sorts by timestamp according to the requested
    timeOrdering, independent of the order the values were submitted in."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)
    asset_id = _create_asset(ctx, client, model_id)

    base = int(time.time()) - 30
    timestamps = [base, base + 5, base + 10]
    values_by_time = [1.0, 2.0, 3.0]
    # Submit out of chronological order: a target that merely echoes insertion
    # order (instead of sorting by timestamp) must fail this.
    submit_order = [2, 0, 1]
    entries = [{
        "entryId": "e1",
        "assetId": asset_id,
        "propertyId": prop_id,
        "propertyValues": [
            {
                "value": {"doubleValue": values_by_time[i]},
                "timestamp": {"timeInSeconds": timestamps[i], "offsetInNanos": 0},
                "quality": "GOOD",
            }
            for i in submit_order
        ],
    }]
    resp = client.batch_put_asset_property_value(entries=entries)
    assert resp["errorEntries"] == [], resp["errorEntries"]

    ascending = _poll_history(client, asset_id, prop_id, base, "ASCENDING")
    assert [h["timestamp"]["timeInSeconds"] for h in ascending] == timestamps, ascending
    assert [h["value"]["doubleValue"] for h in ascending] == values_by_time, ascending

    descending = client.get_asset_property_value_history(
        assetId=asset_id, propertyId=prop_id,
        startDate=_window_start(base), endDate=_window_end(base),
        timeOrdering="DESCENDING",
    )["assetPropertyValueHistory"]
    assert [h["timestamp"]["timeInSeconds"] for h in descending] == list(reversed(timestamps)), descending
    assert [h["value"]["doubleValue"] for h in descending] == list(reversed(values_by_time)), descending


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


def _window_start(base):
    return datetime.fromtimestamp(base - 5, tz=timezone.utc)


def _window_end(base):
    return datetime.fromtimestamp(base + 30, tz=timezone.utc)


def _poll_history(client, asset_id, prop_id, base, time_ordering, timeout_s=60.0, interval_s=3.0):
    start = _window_start(base)
    end = _window_end(base)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_asset_property_value_history(
            assetId=asset_id, propertyId=prop_id,
            startDate=start, endDate=end, timeOrdering=time_ordering,
        )
        if len(resp["assetPropertyValueHistory"]) >= 3:
            return resp["assetPropertyValueHistory"]
        time.sleep(interval_s)
    raise AssertionError("history never contained all 3 ingested values")


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real-check": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(
        assetName=name, assetModelId=model_id, tags={"sim2real-check": CHECK}
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset(assetId=asset_id)))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
