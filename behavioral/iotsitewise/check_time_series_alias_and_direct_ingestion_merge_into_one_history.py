"""time-series-alias-and-direct-ingestion-merge-into-one-history."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "time-series-alias-and-direct-ingestion-merge-into-one-history"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once a disassociated alias time series is associated to an asset property, values ingested
    by propertyAlias and values ingested by assetId/propertyId land in the SAME history timeline,
    addressable through EITHER identifier."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[{"name": "Flow", "dataType": "DOUBLE", "type": {"measurement": {}}}],
    )
    asset_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-asset-"), model_id)
    property_id = _property_id_by_name(sw, asset_id, "Flow")
    alias = f"/sim2real/{ctx.unique_name('sw-alias').replace('/', '-')}"

    base = int(time.time()) - 300
    t_alias, t_direct = base, base + 30

    sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "via-alias",
                "propertyAlias": alias,
                "propertyValues": [
                    {"value": {"doubleValue": 11.0}, "timestamp": {"timeInSeconds": t_alias}, "quality": "GOOD"}
                ],
            }
        ]
    )

    def _cleanup_ts():
        try:
            sw.delete_time_series(alias=alias)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ts)
    _poll_until(lambda: sw.describe_time_series(alias=alias), lambda r: "timeSeriesId" in r, timeout_s=60.0, interval_s=2.0)

    sw.associate_time_series_to_asset_property(alias=alias, assetId=asset_id, propertyId=property_id)

    def _cleanup_assoc():
        try:
            sw.disassociate_time_series_from_asset_property(alias=alias, assetId=asset_id, propertyId=property_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_assoc)

    put_resp = sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "via-id",
                "assetId": asset_id,
                "propertyId": property_id,
                "propertyValues": [
                    {"value": {"doubleValue": 22.0}, "timestamp": {"timeInSeconds": t_direct}, "quality": "GOOD"}
                ],
            }
        ]
    )
    assert put_resp["errorEntries"] == [], f"expected direct-id ingestion to succeed with no errors: {put_resp['errorEntries']}"

    history_by_id = _poll_until(
        lambda: sw.get_asset_property_value_history(
            assetId=asset_id, propertyId=property_id, startDate=base - 5, endDate=t_direct + 5
        )["assetPropertyValueHistory"],
        lambda h: len(h) >= 2,
        timeout_s=60.0,
        interval_s=2.0,
    )
    values_by_id = sorted(v["value"]["doubleValue"] for v in history_by_id)
    assert values_by_id == [11.0, 22.0], f"expected the alias-ingested and id-ingested values merged: {values_by_id}"

    history_by_alias = sw.get_asset_property_value_history(
        propertyAlias=alias, startDate=base - 5, endDate=t_direct + 5
    )["assetPropertyValueHistory"]
    values_by_alias = sorted(v["value"]["doubleValue"] for v in history_by_alias)
    assert values_by_alias == [11.0, 22.0], f"alias-addressed history should be the same merged timeline: {values_by_alias}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last = None
        if last is not None and predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {"assetModelName": name, "assetModelProperties": properties, "tags": {"sim2real-behav": CHECK}}
    if hierarchies:
        kwargs["assetModelHierarchies"] = hierarchies
    resp = sw.create_asset_model(**kwargs)
    model_id = resp["assetModelId"]

    def _cleanup():
        try:
            sw.delete_asset_model(assetModelId=model_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    state = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id)["assetModelStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=3.0,
    )
    if state != "ACTIVE":
        raise AssertionError(f"asset model did not become ACTIVE (state={state})")
    return model_id


def _create_asset_active(ctx, sw, name, model_id, timeout_s=120.0):
    resp = sw.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real-behav": CHECK})
    asset_id = resp["assetId"]

    def _cleanup():
        try:
            sw.delete_asset(assetId=asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    state = _poll_until(
        lambda: sw.describe_asset(assetId=asset_id)["assetStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=3.0,
    )
    if state != "ACTIVE":
        raise AssertionError(f"asset did not become ACTIVE (state={state})")
    return asset_id


def _property_id_by_name(sw, asset_id, prop_name):
    props = sw.describe_asset(assetId=asset_id)["assetProperties"]
    for p in props:
        if p["name"] == prop_name:
            return p["id"]
    raise AssertionError(f"property {prop_name!r} not found on asset {asset_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
