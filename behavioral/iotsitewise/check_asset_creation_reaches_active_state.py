"""asset-creation-reaches-active-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asset-creation-reaches-active-state"
GROUP = "state-machine"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAsset against an ACTIVE model transitions the asset to ACTIVE and DescribeAsset reflects the model-derived property."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Temperature")

    asset_name = ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(
        assetName=asset_name,
        assetModelId=model_id,
        tags={"sim2real-behav-owner": "check-asset-creation-reaches-active-state"},
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    assert resp["assetStatus"]["state"] in ("CREATING", "ACTIVE"), (
        f"expected CreateAsset state in (CREATING, ACTIVE), got {resp['assetStatus']['state']!r}"
    )

    described = _wait_asset_active(ctx, asset_id)
    assert described["assetStatus"]["state"] == "ACTIVE", (
        f"expected DescribeAsset state ACTIVE, got {described['assetStatus']['state']!r}"
    )
    assert described["assetName"] == asset_name, (
        f"expected assetName {asset_name!r}, got {described['assetName']!r}"
    )
    assert described["assetModelId"] == model_id, (
        f"expected assetModelId {model_id!r}, got {described['assetModelId']!r}"
    )
    props = {p["name"]: p for p in described["assetProperties"]}
    assert "Temperature" in props, f"expected a Temperature property, got names {sorted(props)!r}"
    assert props["Temperature"]["id"] == property_id, (
        f"expected inherited property id {property_id!r}, got {props['Temperature']['id']!r}"
    )
    assert props["Temperature"]["dataType"] == "DOUBLE", (
        f"expected dataType DOUBLE, got {props['Temperature']['dataType']!r}"
    )


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
        tags={"sim2real-behav-owner": "check-asset-creation-reaches-active-state"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    described = sw.describe_asset_model(assetModelId=model_id)
    prop = next(p for p in described["assetModelProperties"] if p["name"] == prop_name)
    return model_id, prop["id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
