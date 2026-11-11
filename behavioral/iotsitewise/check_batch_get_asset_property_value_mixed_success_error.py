"""batch-get-asset-property-value-mixed-success-error."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-asset-property-value-mixed-success-error"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetAssetPropertyValue returns a successEntries item for a valid property and an errorEntries item for a nonexistent one, without failing the whole call."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Flow")
    asset_id = _create_asset(ctx, model_id)

    ts = int(time.time()) - 20
    put_resp = sw.batch_put_asset_property_value(entries=[{
        "entryId": "seed",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 7.0}, "timestamp": {"timeInSeconds": ts}, "quality": "GOOD"}],
    }])
    assert put_resp["errorEntries"] == [], f"expected seed write to fully succeed, got errorEntries={put_resp['errorEntries']}"
    _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp=ts)

    bogus_asset_id = str(uuid.uuid4())
    bogus_property_id = str(uuid.uuid4())
    batch_resp = sw.batch_get_asset_property_value(entries=[
        {"entryId": "good", "assetId": asset_id, "propertyId": property_id},
        {"entryId": "bad", "assetId": bogus_asset_id, "propertyId": bogus_property_id},
    ])

    success_by_id = {e["entryId"]: e for e in batch_resp["successEntries"]}
    error_by_id = {e["entryId"]: e for e in batch_resp["errorEntries"]}
    assert "good" in success_by_id, f"expected 'good' entry to succeed, got successEntries={batch_resp['successEntries']}"
    assert success_by_id["good"]["assetPropertyValue"]["value"]["doubleValue"] == 7.0, (
        f"expected the seeded value 7.0 back for 'good', got {success_by_id['good']['assetPropertyValue']}"
    )
    assert "good" not in error_by_id, f"expected 'good' to be absent from errorEntries, got {error_by_id.get('good')}"
    assert "bad" in error_by_id, f"expected 'bad' entry to fail, got errorEntries={batch_resp['errorEntries']}"
    assert error_by_id["bad"]["errorCode"] == "ResourceNotFoundException", (
        f"expected 'bad' errorCode ResourceNotFoundException, got {error_by_id['bad']}"
    )
    assert "bad" not in success_by_id, f"expected 'bad' to be absent from successEntries, got {success_by_id.get('bad')}"


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
            last = resp["propertyValue"]
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
