"""delete-asset-model-with-asset-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-asset-model-with-asset-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an asset model that still has an ACTIVE asset is rejected; the model is only deletable once the asset is fully gone."""
    sw = ctx.client("iotsitewise")
    model_id, _property_id = _create_asset_model_with_measurement(ctx)
    asset_id = _create_asset(ctx, model_id)

    error = _client_error(lambda: sw.delete_asset_model(assetModelId=model_id))
    assert error.get("Code") == "InvalidRequestException", (
        f"deleting an asset model with a live asset returned {error.get('Code')!r}, "
        f"expected 'InvalidRequestException'"
    )
    assert error.get("Message") == "Asset model had assets when delete was called", (
        f"unexpected message: {error.get('Message')!r}"
    )

    # effect absent: the model must still exist and still be ACTIVE (independent read)
    still_there = sw.describe_asset_model(assetModelId=model_id)
    assert still_there["assetModelStatus"]["state"] == "ACTIVE", (
        f"the rejected delete left the model in state "
        f"{still_there['assetModelStatus']['state']!r}, expected 'ACTIVE'"
    )

    # positive control: once the dependent asset is fully gone, deleting the model succeeds,
    # proven by an independent read (describe_asset_model), not the delete call's own response
    sw.delete_asset(assetId=asset_id)
    _wait_asset_deleted(ctx, asset_id)
    sw.delete_asset_model(assetModelId=model_id)
    _wait_asset_model_deleted(ctx, model_id)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _wait_asset_deleted(ctx, asset_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sw.describe_asset(assetId=asset_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} was not deleted within {timeout_s}s")


def _wait_asset_model_deleted(ctx, model_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    code = None
    message = None
    while time.monotonic() < deadline:
        try:
            sw.describe_asset_model(assetModelId=model_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message")
            break
        time.sleep(interval_s)
    assert code == "ResourceNotFoundException", (
        f"asset model {model_id} was not deleted within {timeout_s}s (last error code={code!r})"
    )
    expected_message = f"Asset Model with ID {model_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id)
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
