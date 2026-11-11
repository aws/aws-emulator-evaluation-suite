"""concurrent-associate-assets-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-assets-race"
GROUP = "concurrency"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent identical AssociateAssets calls resolve to one winner, every other racer fails
    InvalidRequestException "Child asset already has a parent", and the child is associated exactly once."""
    client = ctx.client("iotsitewise")
    child_model_id, _ = _create_measurement_model(ctx, client)
    parent_model_id, hierarchy_id = _create_model_with_hierarchy(ctx, client, child_model_id)
    parent_asset_id = _create_asset(ctx, client, parent_model_id)
    child_asset_id = _create_asset(ctx, client, child_model_id)
    ctx.on_cleanup(lambda: _safe(lambda: client.disassociate_assets(
        assetId=parent_asset_id, hierarchyId=hierarchy_id, childAssetId=child_asset_id)))

    n_racers = 6
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        outcomes = list(pool.map(
            lambda _: _associate_with_retry(client, parent_asset_id, hierarchy_id, child_asset_id),
            range(n_racers),
        ))

    successes = [o for o in outcomes if o[0] == "SUCCESS"]
    losers = [o for o in outcomes if o[0] != "SUCCESS"]
    assert len(successes) == 1, outcomes
    assert all(code == "InvalidRequestException" for code, _msg in losers), outcomes
    assert all(msg == "Child asset already has a parent" for _code, msg in losers), outcomes

    summaries = client.list_associated_assets(
        assetId=parent_asset_id, hierarchyId=hierarchy_id, traversalDirection="CHILD",
    )["assetSummaries"]
    matching = [s for s in summaries if s["id"] == child_asset_id]
    assert len(matching) == 1, summaries


def _associate_with_retry(client, asset_id, hierarchy_id, child_id, max_attempts=8):
    for _ in range(max_attempts):
        try:
            client.associate_assets(assetId=asset_id, hierarchyId=hierarchy_id, childAssetId=child_id)
            return ("SUCCESS", None)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ConflictingOperationException":
                time.sleep(1.0)
                continue
            return (code, e.response["Error"]["Message"])
    return ("ConflictingOperationException", None)


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# budget.cleanup_timeout for behavioral/iotsitewise, one deadline shared by every teardown.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}
_MODEL_HAS_ASSETS = "Asset model had assets when delete was called"


def _teardown_left(client) -> float:
    held = _TEARDOWN_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _TEARDOWN_DEADLINES[id(client)] = (client, time.monotonic() + _TEARDOWN_RETRY_S)
    return held[1] - time.monotonic()


def _delete_asset(client, asset_id):
    """Delete the asset and wait until it is gone (deletion is asynchronous), so the model delete
    after it is not refused; retry ConflictingOperationException while a disassociate settles."""
    while True:
        try:
            client.delete_asset(assetId=asset_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictingOperationException" or _teardown_left(client) <= 0:
                raise
        time.sleep(2)
    while _teardown_left(client) > 0:
        try:
            client.describe_asset(assetId=asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"asset {asset_id} still describable at the cleanup deadline")


def _delete_asset_model(client, model_id):
    """Delete the model; retry the refusal while its assets are still deleting, every 2 s to the
    cleanup deadline. A gone model is done."""
    while True:
        try:
            client.delete_asset_model(assetModelId=model_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            busy = (err["Code"], err.get("Message")) == ("InvalidRequestException", _MODEL_HAS_ASSETS)
            if not (busy or err["Code"] == "ConflictingOperationException") or _teardown_left(client) <= 0:
                raise
        time.sleep(2)


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
        status = client.describe_asset(assetId=asset_id)["assetStatus"]
        if status["state"] == "ACTIVE":
            return
        if status["state"] == "FAILED":
            raise AssertionError(f"asset entered FAILED state: {status.get('error')}")
        time.sleep(interval_s)
    raise AssertionError("asset never reached ACTIVE")


def _create_measurement_model(ctx, client, name=None):
    name = name or ctx.unique_name("sim2real-behav-model-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelProperties=[
            {"name": "Measurement1", "dataType": "DOUBLE", "type": {"measurement": {}}}
        ],
        tags={"sim2real": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model(client, model_id))
    _poll_model_active(client, model_id)
    prop_id = client.describe_asset_model(assetModelId=model_id)["assetModelProperties"][0]["id"]
    return model_id, prop_id


def _create_model_with_hierarchy(ctx, client, child_model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-parentmodel-")
    resp = client.create_asset_model(
        assetModelName=name,
        assetModelHierarchies=[{"name": "ChildHierarchy", "childAssetModelId": child_model_id}],
        tags={"sim2real": CHECK},
    )
    model_id = resp["assetModelId"]
    ctx.on_cleanup(lambda: _delete_asset_model(client, model_id))
    _poll_model_active(client, model_id)
    hierarchy_id = client.describe_asset_model(assetModelId=model_id)["assetModelHierarchies"][0]["id"]
    return model_id, hierarchy_id


def _create_asset(ctx, client, model_id, name=None):
    name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = client.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": CHECK})
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset(client, asset_id))
    _poll_asset_active(client, asset_id)
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
