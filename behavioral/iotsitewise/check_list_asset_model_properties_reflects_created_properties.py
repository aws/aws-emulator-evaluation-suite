"""list-asset-model-properties-reflects-created-properties."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-asset-model-properties-reflects-created-properties"
GROUP = "state"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssetModelProperties reflects a property defined at model creation, with the correct data type and measurement type."""
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Voltage", data_type="DOUBLE")

    summaries = _poll_model_properties(ctx, model_id, property_id)
    match = next(p for p in summaries if p["id"] == property_id)
    assert match["name"] == "Voltage", f"expected property name 'Voltage', got {match['name']!r}"
    assert match["dataType"] == "DOUBLE", f"expected dataType 'DOUBLE', got {match['dataType']!r}"
    assert "measurement" in match["type"], f"expected a 'measurement' type marker, got {match['type']!r}"


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
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
        tags={"sim2real:managed": "true"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    described = sw.describe_asset_model(assetModelId=model_id)
    prop = next(p for p in described["assetModelProperties"] if p["name"] == prop_name)
    return model_id, prop["id"]


def _poll_model_properties(ctx, model_id, property_id, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    summaries = []
    while time.monotonic() < deadline:
        resp = sw.list_asset_model_properties(assetModelId=model_id)
        summaries = resp["assetModelPropertySummaries"]
        if any(p["id"] == property_id for p in summaries):
            return summaries
        time.sleep(interval_s)
    raise AssertionError(f"property {property_id} never appeared in ListAssetModelProperties for model {model_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
