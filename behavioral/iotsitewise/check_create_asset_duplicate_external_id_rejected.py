"""create-asset-duplicate-external-id-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-asset-duplicate-external-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAsset with an assetExternalId already in use fails ResourceAlreadyExistsException with the exact
    message and leaves the holder intact; once the holder is deleted the same call succeeds, as does an unused id."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(ctx, sw, ctx.unique_name("sim2real-sw-model-"), properties=[])

    external_id = ctx.unique_name("sim2real_sw_ext").replace("-", "_")
    first_resp = sw.create_asset(
        assetName=ctx.unique_name("sim2real-sw-asset-"),
        assetModelId=model_id,
        assetExternalId=external_id,
        tags={"sim2real": CHECK},
    )
    first_asset_id = first_resp["assetId"]
    _wait_asset_active(sw, first_asset_id)
    first_deleted = False

    def _cleanup_first():
        if first_deleted:
            return
        try:
            sw.delete_asset(assetId=first_asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_first)

    code, message = _error(
        lambda: sw.create_asset(
            assetName=ctx.unique_name("sim2real-sw-asset-dup-"), assetModelId=model_id, assetExternalId=external_id
        )
    )
    assert code == "ResourceAlreadyExistsException", f"unexpected code: {code}"
    assert message == "Another asset is already using the same externalId", f"unexpected message: {message!r}"

    # Effect absent: the external id still resolves to exactly the first asset.
    described = sw.describe_asset(assetId=f"externalId:{external_id}")
    assert described["assetId"] == first_asset_id, (
        f"externalId lookup drifted: expected {first_asset_id}, got {described['assetId']}"
    )

    # Restore leg: once the holder is gone, the external id is free and the identical call succeeds.
    sw.delete_asset(assetId=first_asset_id)
    _wait_asset_deleted(sw, first_asset_id)
    first_deleted = True
    freed_code, freed_message = _error(lambda: sw.describe_asset(assetId=f"externalId:{external_id}"))
    assert freed_code == "ResourceNotFoundException", f"unexpected code: {freed_code}"
    expected_freed = f"asset with externalId: {external_id} doesn't exist."
    assert freed_message == expected_freed, f"expected message {expected_freed!r}, got {freed_message!r}"

    restored_resp = sw.create_asset(
        assetName=ctx.unique_name("sim2real-sw-asset-restored-"),
        assetModelId=model_id,
        assetExternalId=external_id,
        tags={"sim2real": CHECK},
    )
    restored_asset_id = restored_resp["assetId"]

    def _cleanup_restored():
        try:
            sw.delete_asset(assetId=restored_asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_restored)
    assert restored_asset_id != first_asset_id

    # Positive control: a fresh, unused external id creates fine too.
    other_external_id = ctx.unique_name("sim2real_sw_ext2").replace("-", "_")
    second_resp = sw.create_asset(
        assetName=ctx.unique_name("sim2real-sw-asset-"),
        assetModelId=model_id,
        assetExternalId=other_external_id,
        tags={"sim2real": CHECK},
    )
    second_asset_id = second_resp["assetId"]

    def _cleanup_second():
        try:
            sw.delete_asset(assetId=second_asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_second)
    assert second_asset_id != first_asset_id
    assert second_asset_id != restored_asset_id


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_asset_active(sw, asset_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = sw.describe_asset(assetId=asset_id)["assetStatus"]["state"]
        if state == "ACTIVE":
            return
        if state == "FAILED":
            raise AssertionError(f"asset {asset_id} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} did not reach ACTIVE within {timeout_s}s (last={state})")


def _wait_asset_deleted(sw, asset_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sw.describe_asset(assetId=asset_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} was not deleted within {timeout_s}s")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {"assetModelName": name, "assetModelProperties": properties, "tags": {"sim2real": CHECK}}
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
