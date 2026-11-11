"""associate-time-series-to-asset-property-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-time-series-to-asset-property-lifecycle"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An orphan time series created via BatchPutAssetPropertyValue(propertyAlias=...) can be
    associated to a specific asset property with AssociateTimeSeriesToAssetProperty, then
    disassociated back to an orphan with DisassociateTimeSeriesFromAssetProperty."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)
    asset_id = _create_asset(ctx, client, model_id)

    alias = ctx.unique_name("/sim2real/behav/lifecycle-")
    now = int(time.time())
    client.batch_put_asset_property_value(entries=[{
        "entryId": "e1",
        "propertyAlias": alias,
        "propertyValues": [
            {"value": {"doubleValue": 7.0}, "timestamp": {"timeInSeconds": now, "offsetInNanos": 0}, "quality": "GOOD"}
        ],
    }])
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_time_series(alias=alias)))

    orphan = _poll_time_series(client, alias)
    assert "assetId" not in orphan and "propertyId" not in orphan, orphan

    client.associate_time_series_to_asset_property(alias=alias, assetId=asset_id, propertyId=prop_id)
    associated = _poll_time_series_matches(client, alias, lambda ts: ts.get("assetId") == asset_id and ts.get("propertyId") == prop_id)
    assert associated["assetId"] == asset_id, f"expected assetId {asset_id}, got {associated.get('assetId')}"
    assert associated["propertyId"] == prop_id, f"expected propertyId {prop_id}, got {associated.get('propertyId')}"

    client.disassociate_time_series_from_asset_property(alias=alias, assetId=asset_id, propertyId=prop_id)
    detached = _poll_time_series_matches(client, alias, lambda ts: "assetId" not in ts and "propertyId" not in ts)
    assert "assetId" not in detached and "propertyId" not in detached, detached


def _poll_time_series(client, alias, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return client.describe_time_series(alias=alias)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError("orphan time series never became visible")


def _poll_time_series_matches(client, alias, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_time_series(alias=alias)
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"time series never reached expected state: {last}")


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
