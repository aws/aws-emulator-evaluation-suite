"""get-asset-property-aggregates-average."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-asset-property-aggregates-average"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAssetPropertyAggregates over raw values in one 1h bucket returns average 25.0, maximum 40.0 and minimum
    10.0; SiteWise computes aggregates asynchronously, so the check polls until the bucket counts all four values."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)
    asset_id = _create_asset(ctx, client, model_id)

    # Stamp in the past (SiteWise rejects timestamps over 10 min ahead) and keep base..base+3
    # inside one UTC hour bucket wherever now falls in the hour.
    base = int(time.time()) - 10
    hour_start = (base // 3600) * 3600
    base = min(base, hour_start + 3596)
    values = [10.0, 20.0, 30.0, 40.0]
    entries = [{
        "entryId": "e1",
        "assetId": asset_id,
        "propertyId": prop_id,
        "propertyValues": [
            {
                "value": {"doubleValue": v},
                "timestamp": {"timeInSeconds": base + i, "offsetInNanos": 0},
                "quality": "GOOD",
            }
            for i, v in enumerate(values)
        ],
    }]
    resp = client.batch_put_asset_property_value(entries=entries)
    assert resp["errorEntries"] == [], resp["errorEntries"]

    start = datetime.fromtimestamp(hour_start, tz=timezone.utc)
    end = datetime.fromtimestamp(hour_start + 3600, tz=timezone.utc)

    left = ctx.time_left()
    timeout_s = 150.0 if left is None else max(1.0, min(150.0, left - 10.0))
    aggregated = _poll_aggregates(client, asset_id, prop_id, start, end, timeout_s=timeout_s)
    assert aggregated is not None, "aggregates never appeared"
    assert aggregated.get("count") == 4.0, (
        f"expected the bucket to count all 4 values within {timeout_s:.0f}s, got {aggregated!r}"
    )
    assert aggregated["average"] == 25.0, f"expected average 25.0, got {aggregated['average']}"
    assert aggregated["maximum"] == 40.0, f"expected maximum 40.0, got {aggregated['maximum']}"
    assert aggregated["minimum"] == 10.0, f"expected minimum 10.0, got {aggregated['minimum']}"


def _poll_aggregates(client, asset_id, prop_id, start, end, timeout_s=150.0, interval_s=5.0):
    """The bucket's aggregates once they count every written value, else the last ones read."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        resp = client.get_asset_property_aggregates(
            assetId=asset_id,
            propertyId=prop_id,
            aggregateTypes=["AVERAGE", "COUNT", "MAXIMUM", "MINIMUM"],
            resolution="1h",
            startDate=start,
            endDate=end,
        )
        if resp["aggregatedValues"]:
            last = resp["aggregatedValues"][0]["value"]
            if last.get("count") == 4.0:
                return last
        if time.monotonic() + interval_s >= deadline:
            return last
        time.sleep(interval_s)


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_asset_and_wait(client, asset_id, timeout_s=180.0, interval_s=3.0):
    """DeleteAsset is asynchronous and the model's own delete is refused while the asset exists."""
    _safe(lambda: client.delete_asset(assetId=asset_id))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_asset(assetId=asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} still exists {timeout_s:.0f}s after DeleteAsset")


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
        tags={"sim2real-behav": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(
        assetName=name, assetModelId=model_id, tags={"sim2real-behav": CHECK}
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_and_wait(client, asset_id))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
