"""batch-get-asset-property-value-partial-failure."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-asset-property-value-partial-failure"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetAssetPropertyValue partially fails: a valid entry lands in successEntries while an
    entry referencing a nonexistent asset/property lands in errorEntries with ResourceNotFoundException,
    within the SAME request."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[{"name": "Flow", "dataType": "DOUBLE", "type": {"measurement": {}}}],
    )
    asset_id = _create_asset_active(ctx, sw, ctx.unique_name("sim2real-sw-asset-"), model_id)
    property_id = _property_id_by_name(sw, asset_id, "Flow")

    now_seconds = int(time.time())
    put_resp = sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "put1",
                "assetId": asset_id,
                "propertyId": property_id,
                "propertyValues": [
                    {"value": {"doubleValue": 99.0}, "timestamp": {"timeInSeconds": now_seconds}, "quality": "GOOD"}
                ],
            }
        ]
    )
    assert put_resp["errorEntries"] == [], f"expected seed write to succeed, got errors {put_resp['errorEntries']}"
    _poll_until(
        lambda: sw.get_asset_property_value(assetId=asset_id, propertyId=property_id),
        lambda r: "propertyValue" in r,
        timeout_s=60.0,
        interval_s=2.0,
    )

    missing_asset_id = str(uuid.uuid4())
    resp = sw.batch_get_asset_property_value(
        entries=[
            {"entryId": "good", "assetId": asset_id, "propertyId": property_id},
            {"entryId": "bad", "assetId": missing_asset_id, "propertyId": property_id},
        ]
    )

    success_by_id = {e["entryId"]: e for e in resp["successEntries"]}
    error_by_id = {e["entryId"]: e for e in resp["errorEntries"]}

    assert "good" in success_by_id, f"expected 'good' entry to succeed, got {resp}"
    got_value = success_by_id["good"]["assetPropertyValue"]["value"]["doubleValue"]
    assert got_value == 99.0, f"expected 'good' entry to read back 99.0, got {got_value}"

    assert "bad" in error_by_id, f"expected 'bad' entry to fail, got {resp}"
    bad_code = error_by_id["bad"]["errorCode"]
    assert bad_code == "ResourceNotFoundException", f"expected ResourceNotFoundException for 'bad', got {bad_code}"
    assert "good" not in error_by_id, f"expected 'good' entry absent from errorEntries, got {error_by_id}"
    assert "bad" not in success_by_id, f"expected 'bad' entry absent from successEntries, got {success_by_id}"


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
