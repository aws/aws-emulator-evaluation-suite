"""tag-resource-too-many-tags-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource is rejected with LimitExceededException once a resource already carries the
    maximum of 50 tags; the resource keeps exactly 50 tags (the new key is not added), and
    freeing a slot lets a new tag land."""
    client = ctx.client("iotsitewise")
    model_id, _ = _create_measurement_model(ctx, client)
    arn = client.describe_asset_model(assetModelId=model_id)["assetModelArn"]

    fifty_tags = {f"sim2real-behav-tag-{i}": f"v{i}" for i in range(50)}
    client.tag_resource(resourceArn=arn, tags=fifty_tags)
    ctx.on_cleanup(lambda: _safe(lambda: client.untag_resource(
        resourceArn=arn,
        tagKeys=list(fifty_tags.keys()) + ["sim2real-behav-tag-extra", "sim2real-behav-tag-new"],
    )))

    tags_before = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(tags_before) == 50, f"expected 50 pre-existing tags, got {len(tags_before)}"

    code, message = _error(lambda: client.tag_resource(resourceArn=arn, tags={"sim2real-behav-tag-extra": "v"}))
    assert code == "LimitExceededException", f"expected LimitExceededException, got {code}"
    assert message == "Only 50 user tags are allowed on the resource", f"unexpected message: {message!r}"

    # effect absent: still exactly 50 tags, the new key was not added
    tags_after = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(tags_after) == 50, f"expected 50 tags after rejected call, got {len(tags_after)}"
    assert "sim2real-behav-tag-extra" not in tags_after, "rejected tag key was attached anyway"

    # positive control: free a slot, then a new tag lands
    client.untag_resource(resourceArn=arn, tagKeys=["sim2real-behav-tag-0"])
    client.tag_resource(resourceArn=arn, tags={"sim2real-behav-tag-new": "v"})
    tags_final = client.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-behav-tag-new" in tags_final, "new tag did not land after freeing a slot"
    assert "sim2real-behav-tag-0" not in tags_final, "untagged key reappeared"
    assert len(tags_final) == 50, f"expected 50 tags after swap, got {len(tags_final)}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected TagResource to be rejected, but it SUCCEEDED and returned {result!r}")


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
