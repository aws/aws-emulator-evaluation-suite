"""delete-asset-conflict-when-hierarchy-associated-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-asset-conflict-when-hierarchy-associated-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAsset on a parent asset that still has an associated child under its hierarchy is
    rejected with InvalidRequestException; disassociating first allows deletion to succeed."""
    client = ctx.client("iotsitewise")

    child_model_id, _ = _create_measurement_model(ctx, client)
    parent_model_id, hierarchy_id = _create_model_with_hierarchy(ctx, client, child_model_id)

    parent_asset_id = _create_asset(ctx, client, parent_model_id)
    child_asset_id = _create_asset(ctx, client, child_model_id)

    client.associate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)

    code, message = _error(lambda: client.delete_asset(assetId=parent_asset_id))
    assert code == "InvalidRequestException", code
    expected_message = (
        "You must disassociate the asset from all of its children assets before you can delete it."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: parent asset is still there, untouched
    described = client.describe_asset(assetId=parent_asset_id)
    assert described["assetStatus"]["state"] == "ACTIVE"

    # positive control: disassociate, then deletion succeeds
    client.disassociate_assets(assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)
    client.delete_asset(assetId=parent_asset_id)
    _poll_asset_gone(client, parent_asset_id)


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


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


def _poll_asset_gone(client, asset_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_asset(assetId=asset_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("asset was never deleted")


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_model_with_hierarchy(ctx, client, child_model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-parentmodel-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelHierarchies=[{"name": "ChildHierarchy", "childAssetModelId": child_model_id}],
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    hierarchy_id = client.describe_asset_model(assetModelId=model_id)["assetModelHierarchies"][0]["id"]
    return model_id, hierarchy_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(assetName=name, assetModelId=model_id)
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset(assetId=asset_id)))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
