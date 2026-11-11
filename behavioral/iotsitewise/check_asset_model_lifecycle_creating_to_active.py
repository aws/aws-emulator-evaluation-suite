"""asset-model-lifecycle-creating-to-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-model-lifecycle-creating-to-active"
GROUP = "state"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssetModel transitions CREATING -> ACTIVE, DescribeAssetModel reflects the final
    state, and DeleteAssetModel makes the model unreadable and unmutable at the same id."""
    client = ctx.client("iotsitewise")
    name = ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real": "asset-model-lifecycle-creating-to-active"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))

    initial_state = resp["assetModelStatus"]["state"]
    assert initial_state in ("CREATING", "ACTIVE"), initial_state

    _poll_model_active(client, model_id)

    described = client.describe_asset_model(assetModelId=model_id)
    assert described["assetModelName"] == name, (
        f"expected assetModelName {name!r}, got {described['assetModelName']!r}"
    )
    assert described["assetModelStatus"]["state"] == "ACTIVE", (
        f"expected state ACTIVE, got {described['assetModelStatus']!r}"
    )
    assert len(described["assetModelProperties"]) == 1, (
        f"expected exactly 1 property, got {described['assetModelProperties']!r}"
    )
    assert described["assetModelProperties"][0]["dataType"] == "DOUBLE", (
        f"expected dataType DOUBLE, got {described['assetModelProperties'][0]!r}"
    )

    client.delete_asset_model(assetModelId=model_id)
    _poll_model_deleted(client, model_id)

    expected_message = f"Asset Model with ID {model_id} not found"
    describe_code, describe_message = _error(lambda: client.describe_asset_model(assetModelId=model_id))
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on describe of deleted model, got {describe_code!r}"
    )
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )
    delete_code, delete_message = _error(lambda: client.delete_asset_model(assetModelId=model_id))
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on delete of already-deleted model, got {delete_code!r}"
    )
    assert delete_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_message!r}"
    )


def _poll_model_active(client, model_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_asset_model(assetModelId=model_id)["assetModelStatus"]
        state = status["state"]
        if state == "ACTIVE":
            return
        if state == "FAILED":
            raise AssertionError(f"asset model entered FAILED state: {status.get('error')}")
        time.sleep(interval_s)
    raise AssertionError(f"asset model never reached ACTIVE within {timeout_s}s")


def _poll_model_deleted(client, model_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_asset_model(assetModelId=model_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            raise AssertionError(f"unexpected error while polling for deletion: {code}")
        time.sleep(interval_s)
    raise AssertionError(f"asset model {model_id} was not deleted within {timeout_s}s")


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
