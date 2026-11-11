"""delete-asset-model-ifnonematch-active-version-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-asset-model-ifnonematch-active-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAssetModel with If-None-Match: * and Match-For-Version-Type: ACTIVE is rejected with
    PreconditionFailedException BECAUSE an ACTIVE version already exists; the model survives. The
    identical delete call WITHOUT that conditional header (positive control) succeeds."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(ctx, sw, ctx.unique_name("sim2real-sw-model-"), properties=[])

    code, message = _expect_rejected(
        lambda: sw.delete_asset_model(assetModelId=model_id, ifNoneMatch="*", matchForVersionType="ACTIVE")
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got: {code}"
    assert message == "Precondition failed for provided If-None-Match value.", f"unexpected message: {message!r}"

    # Effect absent: the model is still there and still ACTIVE.
    described = sw.describe_asset_model(assetModelId=model_id)
    assert described["assetModelStatus"]["state"] == "ACTIVE", (
        f"expected ACTIVE after the rejected delete, got: {described['assetModelStatus']['state']}"
    )

    # Positive control: the unconditional delete succeeds.
    sw.delete_asset_model(assetModelId=model_id)
    final_code, final_message = _poll_until(
        lambda: _describe_model_error(sw, model_id),
        lambda err: err[0] == "ResourceNotFoundException",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after the unconditional delete, got: {final_code}"
    )
    expected_message = f"Asset Model with ID {model_id} not found"
    assert final_message == expected_message, f"expected message {expected_message!r}, got {final_message!r}"


def _describe_model_error(sw, model_id):
    """Poll probe: (code, message) once DescribeAssetModel fails, (None, state) while it still reads."""
    try:
        described = sw.describe_asset_model(assetModelId=model_id)
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return None, described["assetModelStatus"]["state"]


def _expect_rejected(fn):
    """Call fn(); return the ClientError code and message. An unexpected SUCCESS raises immediately,
    because a target that performs the conditional delete anyway is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the conditional delete to be rejected, but it SUCCEEDED: {result!r}")


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
