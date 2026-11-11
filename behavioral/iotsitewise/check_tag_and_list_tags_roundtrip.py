"""tag-and-list-tags-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-list-tags-roundtrip"
GROUP = "control-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource / UntagResource round-trip cleanly through ListTagsForResource."""
    client = ctx.client("iotsitewise")
    model_id, _ = _create_measurement_model(ctx, client)
    arn = client.describe_asset_model(assetModelId=model_id)["assetModelArn"]

    client.tag_resource(resourceArn=arn, tags={"sim2real-behav-env": "test", "sim2real-behav-owner": "ci"})
    tags = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-behav-env") == "test", f"expected sim2real-behav-env=test, got {tags!r}"
    assert tags.get("sim2real-behav-owner") == "ci", f"expected sim2real-behav-owner=ci, got {tags!r}"
    assert tags == {"sim2real-behav-env": "test", "sim2real-behav-owner": "ci"}, (
        f"expected exactly the two tags just attached and no others, got {tags!r}"
    )

    client.untag_resource(resourceArn=arn, tagKeys=["sim2real-behav-owner"])
    tags2 = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-behav-owner" not in tags2, f"untag_resource did not remove the key, got {tags2!r}"
    assert tags2.get("sim2real-behav-env") == "test", f"expected sim2real-behav-env=test to survive, got {tags2!r}"
    assert tags2 == {"sim2real-behav-env": "test"}, (
        f"expected only the surviving tag after untag_resource, got {tags2!r}"
    )


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
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_asset_model(assetModelId=model_id)))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
