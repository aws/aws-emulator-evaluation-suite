"""batch-put-partial-failure-resource-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-partial-failure-resource-not-found"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchPutAssetPropertyValue processes entries independently: a valid entry succeeds and is
    retrievable while a sibling entry referencing a nonexistent asset lands in errorEntries with
    ResourceNotFoundException."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)
    asset_id = _create_asset(ctx, client, model_id)

    bogus_asset_id = str(uuid.uuid4())
    ts = int(time.time())
    resp = client.batch_put_asset_property_value(entries=[
        {
            "entryId": "good",
            "assetId": asset_id,
            "propertyId": prop_id,
            "propertyValues": [{"value": {"doubleValue": 5.5}, "timestamp": {"timeInSeconds": ts, "offsetInNanos": 0}, "quality": "GOOD"}],
        },
        {
            "entryId": "bad",
            "assetId": bogus_asset_id,
            "propertyId": prop_id,
            "propertyValues": [{"value": {"doubleValue": 9.9}, "timestamp": {"timeInSeconds": ts, "offsetInNanos": 0}, "quality": "GOOD"}],
        },
    ])

    error_by_entry = {e["entryId"]: e["errors"][0]["errorCode"] for e in resp["errorEntries"]}
    assert error_by_entry.get("bad") == "ResourceNotFoundException", error_by_entry
    assert "good" not in error_by_entry, error_by_entry

    value = _poll_value(client, asset_id, prop_id)
    assert value["value"]["doubleValue"] == 5.5, value


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


def _poll_value(client, asset_id, prop_id, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = client.get_asset_property_value(assetId=asset_id, propertyId=prop_id)
            return resp["propertyValue"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError("property value never appeared")


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
