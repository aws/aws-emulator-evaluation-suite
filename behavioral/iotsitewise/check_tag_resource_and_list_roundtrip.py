"""tag-resource-and-list-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-and-list-roundtrip"
GROUP = "state"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and UntagResource removes a subset of them."""
    sw = ctx.client("iotsitewise")
    model_id, _property_id = _create_asset_model_with_measurement(ctx)
    resource_arn = sw.describe_asset_model(assetModelId=model_id)["assetModelArn"]

    sw.tag_resource(resourceArn=resource_arn, tags={"sim2real-env": "behavioral", "sim2real-owner": "check"})
    tags = sw.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert tags == {"sim2real-env": "behavioral", "sim2real-owner": "check"}, (
        f"expected exactly the two tags just attached, got {tags!r}"
    )

    sw.untag_resource(resourceArn=resource_arn, tagKeys=["sim2real-owner"])
    remaining = sw.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert remaining == {"sim2real-env": "behavioral"}, (
        f"expected only sim2real-owner removed, got {remaining!r}"
    )


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
