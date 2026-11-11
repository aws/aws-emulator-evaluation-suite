"""asset-model-composite-model-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-model-composite-model-lifecycle"
GROUP = "control"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssetModelCompositeModel adds a nested composite model (with its own properties) to an
    existing asset model and drives the parent model back through UPDATING -> ACTIVE;
    DescribeAssetModelCompositeModel reflects it, and DeleteAssetModelCompositeModel removes it."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(
        ctx,
        sw,
        ctx.unique_name("sim2real-sw-model-"),
        properties=[{"name": "Speed", "dataType": "DOUBLE", "type": {"measurement": {}}}],
    )

    composite_resp = sw.create_asset_model_composite_model(
        assetModelId=model_id,
        assetModelCompositeModelName="Motor",
        assetModelCompositeModelType="CUSTOM",
        assetModelCompositeModelProperties=[
            {"name": "Rpm", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
    )
    composite_id = composite_resp["assetModelCompositeModelId"]

    def _cleanup_composite():
        try:
            sw.delete_asset_model_composite_model(assetModelId=model_id, assetModelCompositeModelId=composite_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_composite)

    final_state = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id)["assetModelStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert final_state == "ACTIVE", f"expected asset model {model_id} ACTIVE after composite-model create, got {final_state}"

    described = sw.describe_asset_model_composite_model(
        assetModelId=model_id, assetModelCompositeModelId=composite_id
    )
    assert described["assetModelCompositeModelName"] == "Motor", (
        f"expected composite model name 'Motor', got {described['assetModelCompositeModelName']!r}"
    )
    assert described["assetModelCompositeModelType"] == "CUSTOM", (
        f"expected composite model type 'CUSTOM', got {described['assetModelCompositeModelType']!r}"
    )
    prop_names = {p["name"] for p in described["assetModelCompositeModelProperties"]}
    assert prop_names == {"Rpm"}, f"expected composite model properties {{'Rpm'}}, got {prop_names!r}"

    sw.delete_asset_model_composite_model(assetModelId=model_id, assetModelCompositeModelId=composite_id)
    _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id)["assetModelStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    expected_message = f"CompositeModel: {composite_id} not found for AssetModel: {model_id}"
    final_code, final_message = _error(
        lambda: sw.describe_asset_model_composite_model(assetModelId=model_id, assetModelCompositeModelId=composite_id)
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted composite model, got {final_code!r}"
    )
    assert final_message == expected_message, f"expected message {expected_message!r}, got {final_message!r}"

    mutate_code, mutate_message = _error(
        lambda: sw.update_asset_model_composite_model(
            assetModelId=model_id,
            assetModelCompositeModelId=composite_id,
            assetModelCompositeModelName="Motor",
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateAssetModelCompositeModel on a deleted composite model to raise "
        f"ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_message == expected_message, f"expected message {expected_message!r}, got {mutate_message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {"assetModelName": name, "assetModelProperties": properties}
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
