"""concurrent-asset-model-updates-etag-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-asset-model-updates-etag-race"
GROUP = "concurrency"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateAssetModel calls with the same ifMatch ETag: exactly one wins, the other gets the exact
    refusal for when it arrived (stale ETag, or the model still updating), and the model settles ACTIVE with the
    winner's name."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(ctx, sw, ctx.unique_name("sim2real-sw-model-"), properties=[])

    etag = sw.describe_asset_model(assetModelId=model_id)["eTag"]
    name_a = ctx.unique_name("sim2real-sw-racer-a-")
    name_b = ctx.unique_name("sim2real-sw-racer-b-")

    def _update(new_name):
        try:
            sw.update_asset_model(
                assetModelId=model_id, assetModelName=new_name, ifMatch=etag,
                matchForVersionType="LATEST",
            )
            return ("ok", new_name, None)
        except ClientError as err:
            return ("error", new_name, err.response["Error"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_update, [name_a, name_b]))

    outcomes = {name: (status, code) for status, name, code in results}
    successes = [name for name, (status, _) in outcomes.items() if status == "ok"]
    failures = [(name, code) for name, (status, code) in outcomes.items() if status == "error"]

    assert len(successes) == 1, f"expected exactly one racer to win the optimistic lock, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one racer to lose the optimistic lock, got {outcomes}"
    loser = failures[0][1]
    # Which refusal the loser gets depends on when it arrives: after the winner's write it holds a
    # stale ETag; while that write is still being applied the model is in use.
    if loser["Code"] == "ConflictingOperationException":
        expected = f'AssetModel "{model_id}" is in use'
    else:
        assert loser["Code"] == "PreconditionFailedException", f"unexpected loser error code: {outcomes}"
        expected = "Provided If-Match value does not match the current latest version ETag."
    assert loser["Message"] == expected, f"expected message {expected!r}, got {outcomes}"

    final_state = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id)["assetModelStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final_state == "ACTIVE", f"expected model to settle ACTIVE after the race, got {final_state!r}"
    final_name = sw.describe_asset_model(assetModelId=model_id)["assetModelName"]
    assert final_name == successes[0], f"model name {final_name!r} does not match the winning racer {successes[0]!r}"


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
    resp = sw.create_asset_model(tags={"sim2real": "true"}, **kwargs)
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
