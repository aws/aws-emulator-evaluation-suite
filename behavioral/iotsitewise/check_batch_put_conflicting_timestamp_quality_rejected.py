"""batch-put-conflicting-timestamp-quality-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-conflicting-timestamp-quality-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A same-timestamp, same-quality put overwrites the stored value; a same-timestamp put with a different
    quality returns no error entry but leaves value 20.0 and quality GOOD unchanged; a new timestamp ingests."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Vibration")
    asset_id = _create_asset(ctx, model_id)

    ts = int(time.time()) - 60
    first = sw.batch_put_asset_property_value(entries=[{
        "entryId": "first",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 10.0}, "timestamp": {"timeInSeconds": ts}, "quality": "GOOD"}],
    }])
    assert first["errorEntries"] == [], f"initial put rejected: {first['errorEntries']}"
    _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp=ts, expect_value=10.0)

    # same timestamp, same quality, different value: NOT a conflict — the value is overwritten.
    overwrite = sw.batch_put_asset_property_value(entries=[{
        "entryId": "overwrite",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 20.0}, "timestamp": {"timeInSeconds": ts}, "quality": "GOOD"}],
    }])
    assert overwrite["errorEntries"] == [], f"same-quality overwrite unexpectedly rejected: {overwrite['errorEntries']}"
    overwritten = _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp=ts, expect_value=20.0)
    assert overwritten["quality"] == "GOOD", f"expected quality GOOD after overwrite, got {overwritten['quality']!r}"

    # same timestamp, DIFFERENT quality: accepted (no error entry) but silently has no effect;
    # no ConflictingOperationException is surfaced.
    conflict = sw.batch_put_asset_property_value(entries=[{
        "entryId": "conflict",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 30.0}, "timestamp": {"timeInSeconds": ts}, "quality": "BAD"}],
    }])
    assert conflict["errorEntries"] == [], f"differing-quality put unexpectedly errored: {conflict['errorEntries']}"

    # effect absent, and stable: 6 independent reads 5s apart all still show the (GOOD, 20.0)
    # overwrite, never the silently-dropped (BAD, 30.0) — a freeze detector, not a bare sleep.
    reads = []
    for _ in range(6):
        time.sleep(5.0)
        reads.append(sw.get_asset_property_value(assetId=asset_id, propertyId=property_id)["propertyValue"])
    for unchanged in reads:
        assert unchanged["timestamp"]["timeInSeconds"] == ts, f"timestamp moved: {unchanged}"
        assert unchanged["value"]["doubleValue"] == 20.0, f"value changed by the differing-quality put: {unchanged}"
        assert unchanged["quality"] == "GOOD", f"quality changed by the differing-quality put: {unchanged}"

    # positive control: a genuinely new timestamp ingests without conflict
    control = sw.batch_put_asset_property_value(entries=[{
        "entryId": "control",
        "assetId": asset_id,
        "propertyId": property_id,
        "propertyValues": [{"value": {"doubleValue": 40.0}, "timestamp": {"timeInSeconds": ts + 1}, "quality": "GOOD"}],
    }])
    assert control["errorEntries"] == [], f"control put unexpectedly rejected: {control['errorEntries']}"
    fresh = _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp=ts + 1, expect_value=40.0)
    assert fresh["value"]["doubleValue"] == 40.0, f"control value mismatch: {fresh}"


def _delete_asset_model_best_effort(ctx, model_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset_model(assetModelId=model_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_asset_best_effort(ctx, asset_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.delete_asset(assetId=asset_id)
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


def _wait_asset_active(ctx, asset_id, timeout_s=180.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    state = None
    described = None
    while time.monotonic() < deadline:
        described = sw.describe_asset(assetId=asset_id)
        state = described["assetStatus"]["state"]
        if state == "ACTIVE":
            return described
        if state == "FAILED":
            raise AssertionError(f"asset {asset_id} entered FAILED: {described['assetStatus'].get('error')}")
        time.sleep(interval_s)
    raise AssertionError(f"asset {asset_id} did not reach ACTIVE within {timeout_s}s (last={state})")


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


def _create_asset(ctx, model_id, name=None):
    sw = ctx.client("iotsitewise")
    asset_name = name or ctx.unique_name("sim2real-behav-asset-")
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id)
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _poll_get_property_value(ctx, asset_id, property_id, expect_timestamp, expect_value=None, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sw.get_asset_property_value(assetId=asset_id, propertyId=property_id)
            last = resp["propertyValue"]
            if last["timestamp"]["timeInSeconds"] == expect_timestamp and (
                expect_value is None or last["value"]["doubleValue"] == expect_value
            ):
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(
        f"asset property value with timestamp {expect_timestamp} value {expect_value} never appeared (last={last})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
