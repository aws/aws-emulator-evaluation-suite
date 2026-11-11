"""disassociate-time-series-removes-alias-association."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-time-series-removes-alias-association"
GROUP = "state"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTimeSeries resolves a bound alias to its asset property once data is ingested; after
    DisassociateTimeSeriesFromAssetProperty the alias resolves without assetId/propertyId and its history reads
    by alias but no longer by assetId/propertyId."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Rpm")
    asset_id = _create_asset(ctx, model_id)
    alias = ctx.unique_name("/sim2real-behav/rpm-alias-")

    sw.update_asset_property(assetId=asset_id, propertyId=property_id, propertyAlias=alias)
    assert _property_alias(sw, asset_id, property_id) == alias

    ts = int(time.time()) - 30
    put_resp = sw.batch_put_asset_property_value(entries=[{
        "entryId": "seed",
        "propertyAlias": alias,
        "propertyValues": [{"value": {"doubleValue": 42.0}, "timestamp": {"timeInSeconds": ts}, "quality": "GOOD"}],
    }])
    assert put_resp["errorEntries"] == [], put_resp["errorEntries"]

    described = _poll_time_series_by_alias(ctx, alias, asset_id, property_id)
    assert described["assetId"] == asset_id
    assert described["propertyId"] == property_id

    sw.disassociate_time_series_from_asset_property(alias=alias, assetId=asset_id, propertyId=property_id)
    ctx.on_cleanup(lambda: _delete_time_series_best_effort(ctx, alias))

    orphaned = _poll_until_orphaned(ctx, alias)
    assert "assetId" not in orphaned and "propertyId" not in orphaned, orphaned

    history_by_id = sw.get_asset_property_value_history(
        assetId=asset_id, propertyId=property_id, startDate=ts - 5, endDate=ts + 5
    )["assetPropertyValueHistory"]
    assert history_by_id == [], history_by_id

    history_by_alias = sw.get_asset_property_value_history(
        propertyAlias=alias, startDate=ts - 5, endDate=ts + 5
    )["assetPropertyValueHistory"]
    values_by_alias = [v["value"]["doubleValue"] for v in history_by_alias]
    assert values_by_alias == [42.0], values_by_alias


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


def _poll_time_series_by_alias(ctx, alias, asset_id, property_id, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = sw.describe_time_series(alias=alias)
            if resp.get("assetId") == asset_id and resp.get("propertyId") == property_id:
                return resp
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"time series for alias {alias} never bound to asset {asset_id}/{property_id}")


def _poll_until_orphaned(ctx, alias, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sw.describe_time_series(alias=alias)
        if "assetId" not in last and "propertyId" not in last:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"time series for alias {alias} never reverted to disassociated (last={last})")


def _property_alias(sw, asset_id, property_id):
    described = sw.describe_asset(assetId=asset_id)
    prop = next(p for p in described["assetProperties"] if p["id"] == property_id)
    return prop.get("alias")


def _delete_time_series_best_effort(ctx, alias):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_time_series(alias=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
