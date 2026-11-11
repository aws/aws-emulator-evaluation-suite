"""asset-model-lifecycle-reaches-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-model-lifecycle-reaches-active"
GROUP = "state-machine"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created asset model transitions from CREATING to ACTIVE and DescribeAssetModel
    reflects it; deleting it then makes the model unreadable and unmutatable."""
    sw = ctx.client("iotsitewise")
    model_name = ctx.unique_name("sim2real-behav-model-")
    resp = sw.create_asset_model(assetModelName=model_name, tags={"sim2real": CHECK})
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    initial_state = resp["assetModelStatus"]["state"]
    assert initial_state in ("CREATING", "ACTIVE"), (
        f"expected CreateAssetModel to report CREATING or ACTIVE, got {initial_state!r}"
    )

    described = _wait_asset_model_active(ctx, model_id)
    assert described["assetModelStatus"]["state"] == "ACTIVE", (
        f"expected assetModelStatus.state == ACTIVE, got {described['assetModelStatus']['state']!r}"
    )
    assert described["assetModelName"] == model_name, (
        f"expected assetModelName == {model_name!r}, got {described['assetModelName']!r}"
    )
    assert described["assetModelId"] == model_id, (
        f"expected assetModelId == {model_id!r}, got {described['assetModelId']!r}"
    )

    sw.delete_asset_model(assetModelId=model_id)
    expected_message = f"Asset Model with ID {model_id} not found"
    final_code, final_message = _wait_asset_model_deleted(ctx, model_id)
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted asset model, got {final_code!r}"
    )
    assert final_message == expected_message, f"expected message {expected_message!r}, got {final_message!r}"
    mutation_code, mutation_message = _error(
        lambda: sw.update_asset_model(assetModelId=model_id, assetModelName="sim2real-renamed-after-delete")
    )
    assert mutation_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted asset model, got {mutation_code!r}"
    )
    assert mutation_message == expected_message, (
        f"expected message {expected_message!r}, got {mutation_message!r}"
    )


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


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


def _wait_asset_model_deleted(ctx, model_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sw.describe_asset_model(assetModelId=model_id)
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return last_code, err.response["Error"].get("Message")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset model {model_id} was not deleted within {timeout_s}s (last_error={last_code})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
