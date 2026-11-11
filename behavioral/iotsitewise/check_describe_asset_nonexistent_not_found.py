"""describe-asset-nonexistent-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-asset-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAsset succeeds for a real asset (positive control), then a well-formed but
    never-created assetId is rejected with ResourceNotFoundException."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model(ctx)
    asset_id = _create_asset(ctx, model_id)

    described = sw.describe_asset(assetId=asset_id)
    assert described["assetId"] == asset_id, (
        f"positive control: expected DescribeAsset to return {asset_id!r}, "
        f"got {described['assetId']!r}"
    )

    bogus_asset_id = str(uuid.uuid4())
    error = _client_error(lambda: sw.describe_asset(assetId=bogus_asset_id))
    code = error.get("Code")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created assetId, got {code!r}"
    )
    expected_message = f"Asset with ID {bogus_asset_id} not found"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_asset_model_active(ctx, model_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        described = sw.describe_asset_model(assetModelId=model_id)
        state = described["assetModelStatus"]["state"]
        if state == "ACTIVE":
            return described
        if state == "FAILED":
            raise AssertionError(
                f"asset model {model_id} entered FAILED: "
                f"{described['assetModelStatus'].get('error')}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"asset model {model_id} did not reach ACTIVE within {timeout_s}s (last={state})"
    )


def _wait_asset_active(ctx, asset_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        described = sw.describe_asset(assetId=asset_id)
        state = described["assetStatus"]["state"]
        if state == "ACTIVE":
            return described
        if state == "FAILED":
            raise AssertionError(
                f"asset {asset_id} entered FAILED: {described['assetStatus'].get('error')}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"asset {asset_id} did not reach ACTIVE within {timeout_s}s (last={state})"
    )


def _delete_asset_best_effort(ctx, asset_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset(assetId=asset_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_asset_model(ctx) -> str:
    sw = ctx.client("iotsitewise")
    model_name = ctx.unique_name("sim2real-behav-model-")
    resp = sw.create_asset_model(
        assetModelName=model_name,
        assetModelProperties=[{
            "name": "Value",
            "dataType": "DOUBLE",
            "type": {"measurement": {}},
        }],
        tags={"sim2real-behav-owner": "check-describe-asset-nonexistent-not-found"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    return model_id


def _create_asset(ctx, model_id: str) -> str:
    sw = ctx.client("iotsitewise")
    asset_name = ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(
        assetName=asset_name,
        assetModelId=model_id,
        tags={"sim2real-behav-owner": "check-describe-asset-nonexistent-not-found"},
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
