"""too-many-tags-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with more than 50 tags fails InvalidRequestException with the exact message and attaches none,
    while a one-tag set succeeds."""
    sw = ctx.client("iotsitewise")
    model_id, _property_id = _create_asset_model_with_measurement(ctx)
    resource_arn = sw.describe_asset_model(assetModelId=model_id)["assetModelArn"]

    too_many = {f"sim2real-tag-{i}": str(i) for i in range(51)}
    code, message = _error_code(lambda: sw.tag_resource(resourceArn=resource_arn, tags=too_many))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r} ({message!r})"
    expected_message = (
        "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no tags were attached by the rejected call
    after_reject = sw.list_tags_for_resource(resourceArn=resource_arn).get("tags", {})
    assert after_reject == {}, f"expected no tags after the rejected call, got {after_reject!r}"

    # positive control: a normal-sized tag set still succeeds
    sw.tag_resource(resourceArn=resource_arn, tags={"sim2real-tag-ok": "1"})
    after_control = sw.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert after_control == {"sim2real-tag-ok": "1"}, (
        f"expected the normal-sized tag set to land, got {after_control!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
