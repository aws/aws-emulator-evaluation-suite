"""batch-get-asset-property-aggregates-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-asset-property-aggregates-roundtrip"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetAssetPropertyAggregates computes SUM/COUNT for a batch entry over a 1-minute bucket
    of raw ingested values, landing in successEntries keyed by the caller's entryId."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[{"name": "Weight", "dataType": "DOUBLE", "type": {"measurement": {}}}],
    )
    asset_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-asset-"), model_id)
    property_id = _property_id_by_name(sw, asset_id, "Weight")

    bucket_start = (int(time.time()) - 600) // 60 * 60
    t_a, t_b, t_c = bucket_start + 5, bucket_start + 25, bucket_start + 45
    put_resp = sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "e1",
                "assetId": asset_id,
                "propertyId": property_id,
                "propertyValues": [
                    {"value": {"doubleValue": 5.0}, "timestamp": {"timeInSeconds": t_a}, "quality": "GOOD"},
                    {"value": {"doubleValue": 7.0}, "timestamp": {"timeInSeconds": t_b}, "quality": "GOOD"},
                    {"value": {"doubleValue": 9.0}, "timestamp": {"timeInSeconds": t_c}, "quality": "GOOD"},
                ],
            }
        ]
    )
    assert put_resp["errorEntries"] == [], f"expected no put errors, got {put_resp['errorEntries']}"

    deadline = time.monotonic() + 240.0
    success_entries = None
    while time.monotonic() < deadline:
        resp = sw.batch_get_asset_property_aggregates(
            entries=[
                {
                    "entryId": "agg1",
                    "assetId": asset_id,
                    "propertyId": property_id,
                    "aggregateTypes": ["SUM", "COUNT"],
                    "resolution": "1m",
                    "startDate": bucket_start - 1,
                    "endDate": bucket_start + 60,
                }
            ]
        )
        assert resp["errorEntries"] == [], resp["errorEntries"]
        if resp["successEntries"] and resp["successEntries"][0]["aggregatedValues"]:
            success_entries = resp["successEntries"]
            break
        time.sleep(5.0)

    if success_entries is None:
        raise AssertionError(
            "BatchGetAssetPropertyAggregates did not produce a 1-minute bucket within 240s; "
            "SiteWise aggregate computation latency is not SLA-bound"
        )

    assert success_entries[0]["entryId"] == "agg1", (
        f"expected successEntries keyed by entryId 'agg1', got {success_entries[0]['entryId']!r}"
    )
    values = success_entries[0]["aggregatedValues"][0]["value"]
    assert values["sum"] == 21.0, f"expected sum 21.0 (5.0+7.0+9.0), got {values['sum']}"
    assert values["count"] == 3.0, f"expected count 3.0 (3 ingested values), got {values['count']}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {"assetModelName": name, "assetModelProperties": properties, "tags": {"sim2real": CHECK}}
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
    resp = sw.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": CHECK})
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
