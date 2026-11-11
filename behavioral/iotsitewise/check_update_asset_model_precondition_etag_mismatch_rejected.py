"""update-asset-model-precondition-etag-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-asset-model-precondition-etag-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssetModel with a stale If-Match ETag is rejected with PreconditionFailedException,
    the rejected update never takes effect (name and ETag both unchanged), and the identical call
    retried against the current ETag succeeds and advances the ETag."""
    sw = ctx.client("iotsitewise")
    model_id, _property_id = _create_asset_model_with_measurement(ctx)
    original = sw.describe_asset_model(assetModelId=model_id)
    etag0 = original["eTag"]

    # Positive control: an update against the correct, current ETag succeeds and advances the
    # ETag -- this is what "stale" is stale relative to.
    control_name = ctx.unique_name("sim2real-behav-control-rename-")
    sw.update_asset_model(
        assetModelId=model_id, assetModelName=control_name, ifMatch=etag0,
        matchForVersionType="LATEST",
    )
    after_control = _wait_asset_model_active(ctx, model_id)
    etag1 = after_control["eTag"]
    assert after_control["assetModelName"] == control_name, (
        f"positive control did not apply: expected name {control_name!r}, got "
        f"{after_control['assetModelName']!r}"
    )
    assert etag1 != etag0, f"a successful update must advance the ETag; still {etag1!r}"

    # Break exactly one thing: reuse etag0, which the control update above made stale.
    attempted_name = ctx.unique_name("sim2real-behav-stale-rename-")
    code, message = _error_code(lambda: sw.update_asset_model(
        assetModelId=model_id, assetModelName=attempted_name, ifMatch=etag0,
        matchForVersionType="LATEST",
    ))
    assert code == "PreconditionFailedException", (
        f"a stale If-Match ETag must be rejected with PreconditionFailedException; got {code!r}"
    )
    expected_message = "Provided If-Match value does not match the current latest version ETag."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: an independent read shows the rejected update never applied.
    after_reject = sw.describe_asset_model(assetModelId=model_id)
    assert after_reject["assetModelName"] == control_name, (
        f"a rejected update must not take effect; name became {after_reject['assetModelName']!r}"
    )
    assert after_reject["eTag"] == etag1, (
        f"a rejected update must not advance the ETag; got {after_reject['eTag']!r}"
    )

    # Restore: the identical call now succeeds once it carries the current ETag.
    new_name = ctx.unique_name("sim2real-behav-etag-rename-")
    sw.update_asset_model(
        assetModelId=model_id, assetModelName=new_name, ifMatch=etag1,
        matchForVersionType="LATEST",
    )
    updated = _wait_asset_model_active(ctx, model_id)
    assert updated["assetModelName"] == new_name, (
        f"the restored update must apply; expected name {new_name!r}, got "
        f"{updated['assetModelName']!r}"
    )
    assert updated["eTag"] != etag1, f"a successful update must advance the ETag; still {etag1!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
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
        tags={"sim2real": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model_best_effort(ctx, model_id))
    _wait_asset_model_active(ctx, model_id)
    described = sw.describe_asset_model(assetModelId=model_id)
    prop = next(p for p in described["assetModelProperties"] if p["name"] == prop_name)
    return model_id, prop["id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
