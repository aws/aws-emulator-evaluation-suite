"""describe-asset-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-asset-not-found"
GROUP = "error-semantics"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAsset on a well-formed but nonexistent assetId returns ResourceNotFoundException,
    while the identical call against a real, freshly created ACTIVE asset succeeds — and once
    that asset is deleted, DescribeAsset on its own (now real) id returns the same code."""
    sw = ctx.client("iotsitewise")
    model_id, _property_id = _create_asset_model_with_measurement(ctx)

    asset_name = ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(
        assetName=asset_name, assetModelId=model_id, tags={"sim2real-behav": "describe-asset-not-found"}
    )
    asset_id = resp["assetId"]
    _wait_asset_active(ctx, asset_id)

    # Positive control: without proving DescribeAsset succeeds against a real, ACTIVE
    # asset, "rejects a nonexistent assetId" is indistinguishable from "rejects every
    # DescribeAsset call".
    described = sw.describe_asset(assetId=asset_id)
    assert described["assetId"] == asset_id, described["assetId"]
    assert described["assetStatus"]["state"] == "ACTIVE", described["assetStatus"]

    bogus_id = str(uuid.uuid4())
    code, message = _error(lambda: sw.describe_asset(assetId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Asset with ID {bogus_id} not found", f"unexpected message: {message!r}"

    # This check now deletes something it created — assert the deletion rather than
    # leaving it to a silent, best-effort ctx.on_cleanup: an independent DescribeAsset
    # on the just-deleted id must return the same specific not-found code.
    sw.delete_asset(assetId=asset_id)
    _wait_asset_gone(ctx, asset_id)

    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED: {result!r}")


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _wait_asset_gone(ctx, asset_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            described = sw.describe_asset(assetId=asset_id)
            last_state = described["assetStatus"]["state"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            assert code == "ResourceNotFoundException", (
                f"expected ResourceNotFoundException after delete, got {code}"
            )
            assert message == f"Asset with ID {asset_id} not found", f"unexpected message: {message!r}"
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"asset {asset_id} still describable {timeout_s}s after delete (last state={last_state})"
    )


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


def _create_asset_model_with_measurement(ctx, prop_name="Temperature", data_type="DOUBLE"):
    sw = ctx.client("iotsitewise")
    model_name = ctx.unique_name("sim2real-behav-model-")
    resp = sw.create_asset_model(
        assetModelName=model_name,
        assetModelProperties=[{
            "name": prop_name,
            "dataType": data_type,
            "type": {"measurement": {}},
        }],
        tags={"sim2real-behav": "describe-asset-not-found"},
    )
    model_id = resp["assetModelId"]
    _wait_asset_model_active(ctx, model_id)
    described = sw.describe_asset_model(assetModelId=model_id)
    prop = next(p for p in described["assetModelProperties"] if p["name"] == prop_name)
    return model_id, prop["id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
