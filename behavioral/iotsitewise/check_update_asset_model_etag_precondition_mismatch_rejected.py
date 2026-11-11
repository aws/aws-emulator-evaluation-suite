"""update-asset-model-etag-precondition-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-asset-model-etag-precondition-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssetModel with a stale If-Match ETag is rejected with PreconditionFailedException
    and leaves the model's name unchanged; the identical update with the correct, current ETag
    succeeds."""
    client = ctx.client("iotsitewise")
    model_id, _ = _create_measurement_model(ctx, client)
    described0 = client.describe_asset_model(assetModelId=model_id)
    original_name = described0["assetModelName"]
    current_etag = described0["eTag"]
    bogus_etag = ("x" if current_etag[0] != "x" else "y") + current_etag[1:]
    assert len(bogus_etag) == len(current_etag), (
        f"test setup: bogus etag {bogus_etag!r} must match current etag length {len(current_etag)}"
    )

    new_name = ctx.unique_name("sim2real-behav-model-renamed-")

    code, message = _error_code(lambda: client.update_asset_model(
        assetModelId=model_id, assetModelName=new_name, ifMatch=bogus_etag,
        matchForVersionType="LATEST",
    ))
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code}"
    expected_message = "Provided If-Match value does not match the current latest version ETag."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: name unchanged
    described1 = client.describe_asset_model(assetModelId=model_id)
    assert described1["assetModelName"] == original_name, (
        f"expected name unchanged at {original_name!r}, got {described1['assetModelName']!r}"
    )

    # positive control: the correct current etag succeeds
    client.update_asset_model(
        assetModelId=model_id, assetModelName=new_name, ifMatch=current_etag,
        matchForVersionType="LATEST",
    )
    _poll_model_active(client, model_id)
    described2 = client.describe_asset_model(assetModelId=model_id)
    assert described2["assetModelName"] == new_name, (
        f"expected name updated to {new_name!r}, got {described2['assetModelName']!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
        tags={"sim2real-behav-env": "test", "sim2real-behav-owner": "ci"},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
