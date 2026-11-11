"""asset-property-value-history-quality-filter-excludes-bad-readings."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-property-value-history-quality-filter-excludes-bad-readings"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAssetPropertyValueHistory with qualities=["GOOD"] excludes BAD-quality readings that were
    ingested in the same window, while an unfiltered call still returns both."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[{"name": "Signal", "dataType": "DOUBLE", "type": {"measurement": {}}}],
    )
    asset_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-asset-"), model_id)
    property_id = _property_id_by_name(sw, asset_id, "Signal")

    base = int(time.time()) - 300
    t_good, t_bad = base, base + 10
    put_resp = sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "e1",
                "assetId": asset_id,
                "propertyId": property_id,
                "propertyValues": [
                    {"value": {"doubleValue": 1.0}, "timestamp": {"timeInSeconds": t_good}, "quality": "GOOD"},
                    {"value": {"doubleValue": 2.0}, "timestamp": {"timeInSeconds": t_bad}, "quality": "BAD"},
                ],
            }
        ]
    )
    assert put_resp["errorEntries"] == [], f"batch_put_asset_property_value rejected entries: {put_resp['errorEntries']}"

    unfiltered = _poll_until(
        lambda: sw.get_asset_property_value_history(
            assetId=asset_id, propertyId=property_id, startDate=base - 5, endDate=t_bad + 5
        )["assetPropertyValueHistory"],
        lambda h: len(h) >= 2,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert len(unfiltered) == 2, f"expected both GOOD and BAD readings unfiltered, got {unfiltered}"

    good_only = sw.get_asset_property_value_history(
        assetId=asset_id,
        propertyId=property_id,
        startDate=base - 5,
        endDate=t_bad + 5,
        qualities=["GOOD"],
    )["assetPropertyValueHistory"]
    assert len(good_only) == 1, f"expected only the GOOD reading, got {good_only}"
    assert good_only[0]["quality"] == "GOOD", f"expected quality GOOD, got {good_only[0]['quality']}"
    assert good_only[0]["value"]["doubleValue"] == 1.0, f"expected value 1.0, got {good_only[0]['value']}"
    assert good_only[0]["timestamp"]["timeInSeconds"] == t_good, (
        f"expected timestamp {t_good}, got {good_only[0]['timestamp']['timeInSeconds']}"
    )


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
    kwargs = {"assetModelName": name, "assetModelProperties": properties}
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
    resp = sw.create_asset(assetName=name, assetModelId=model_id)
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
