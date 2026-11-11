"""list-asset-model-properties-reflects-definition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-asset-model-properties-reflects-definition"
GROUP = "control-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssetModelProperties reflects the exact property definition (id, name, dataType, and
    MEASUREMENT type) supplied at CreateAssetModel time."""
    client = ctx.client("iotsitewise")
    model_id, prop_id = _create_measurement_model(ctx, client)

    resp = client.list_asset_model_properties(assetModelId=model_id)
    summaries = resp["assetModelPropertySummaries"]
    matching = [s for s in summaries if s["id"] == prop_id]
    assert len(matching) == 1, summaries
    summary = matching[0]
    assert summary["name"] == "Measurement1", summary["name"]
    assert summary["dataType"] == "DOUBLE", summary["dataType"]
    assert "measurement" in summary["type"], summary["type"]


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


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real-behav-owner": "check", "sim2real-check": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
