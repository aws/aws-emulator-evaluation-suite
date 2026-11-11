"""asset-lifecycle-creating-to-active-with-model."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-lifecycle-creating-to-active-with-model"
GROUP = "state"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAsset from an ACTIVE model transitions CREATING -> ACTIVE and inherits the model's
    property (name + dataType, not just its id); DeleteAsset then makes it independently
    unreachable and a second delete on the same id fails with ResourceNotFoundException."""
    client = ctx.client("iotsitewise")
    model_id, prop_id, prop_name = _create_measurement_model(ctx, client)

    asset_name = ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(
        assetName=asset_name, assetModelId=model_id, tags={"sim2real": CHECK}
    )
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset(assetId=asset_id)))
    assert resp["assetStatus"]["state"] in ("CREATING", "ACTIVE"), (
        f"expected CreateAsset to report CREATING or ACTIVE, got {resp['assetStatus']['state']!r}"
    )

    described = _poll_asset_active(client, asset_id)
    assert described["assetStatus"]["state"] == "ACTIVE", (
        f"expected asset {asset_id} to reach ACTIVE, last state "
        f"{described['assetStatus']['state']!r}"
    )
    assert described["assetModelId"] == model_id, (
        f"expected assetModelId {model_id!r}, got {described['assetModelId']!r}"
    )
    props = {p["id"]: p for p in described["assetProperties"]}
    assert prop_id in props, f"expected inherited property {prop_id!r} in {sorted(props)}"
    assert props[prop_id]["name"] == prop_name, (
        f"expected inherited property name {prop_name!r}, got {props[prop_id]['name']!r}"
    )
    assert props[prop_id]["dataType"] == "DOUBLE", (
        f"expected inherited property dataType 'DOUBLE', got {props[prop_id]['dataType']!r}"
    )

    client.delete_asset(assetId=asset_id)
    _poll_asset_gone(client, asset_id)
    code, message = _error(lambda: client.delete_asset(assetId=asset_id))
    assert code == "ResourceNotFoundException", (
        f"expected a second DeleteAsset on {asset_id} to fail with ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected_message = f"Asset with ID {asset_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


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
        described = client.describe_asset(assetId=asset_id)
        status = described["assetStatus"]
        if status["state"] == "ACTIVE":
            return described
        if status["state"] == "FAILED":
            raise AssertionError(f"asset entered FAILED state: {status.get('error')}")
        time.sleep(interval_s)
    raise AssertionError("asset never reached ACTIVE")


def _poll_asset_gone(client, asset_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = client.describe_asset(assetId=asset_id)["assetStatus"]["state"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(
        f"asset {asset_id} was not gone within {timeout_s}s (last state={last_state!r})"
    )


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    prop_name = "Measurement1"
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": prop_name, "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id, prop_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
