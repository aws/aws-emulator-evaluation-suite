"""property-alias-bind-and-ingest-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "property-alias-bind-and-ingest-roundtrip"
GROUP = "telemetry"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeTimeSeries resolves a bound alias after the first ingest; the latest value is the newest timestamp
    whatever the ingest order, each sample keeps its quality, and the history is ordered by timestamp."""
    sw = ctx.client("iotsitewise")
    model_id, property_id = _create_asset_model_with_measurement(ctx, prop_name="Humidity")
    asset_id = _create_asset(ctx, model_id)
    alias = ctx.unique_name("/sim2real-behav/alias-")

    sw.update_asset_property(assetId=asset_id, propertyId=property_id, propertyAlias=alias)
    ctx.on_cleanup(lambda: _disassociate_alias_best_effort(ctx, alias, asset_id, property_id))

    ts = int(time.time()) - 30
    put_resp = sw.batch_put_asset_property_value(entries=[{
        "entryId": "via-alias",
        "propertyAlias": alias,
        "propertyValues": [{"value": {"doubleValue": 55.5}, "timestamp": {"timeInSeconds": ts}, "quality": "GOOD"}],
    }])
    assert put_resp["errorEntries"] == [], f"expected no error entries, got {put_resp['errorEntries']}"

    described = _poll_time_series_by_alias(ctx, alias, asset_id, property_id)
    assert described["assetId"] == asset_id, f"expected assetId {asset_id}, got {described['assetId']}"
    assert described["propertyId"] == property_id, (
        f"expected propertyId {property_id}, got {described['propertyId']}"
    )
    assert described["dataType"] == "DOUBLE", f"expected dataType DOUBLE, got {described['dataType']}"

    value = _poll_get_property_value_by_alias(ctx, alias, expect_timestamp=ts)
    assert value["value"]["doubleValue"] == 55.5, f"expected 55.5, got {value['value']['doubleValue']}"

    # telemetry ordering: ingest a NEWER sample first, then an OLDER sample second (reverse of
    # timestamp order). "Latest" must track timestamp, not insertion order.
    newer_ts = ts + 60
    older_ts = ts + 30
    put_newer = sw.batch_put_asset_property_value(entries=[{
        "entryId": "newer-first",
        "propertyAlias": alias,
        "propertyValues": [{"value": {"doubleValue": 70.0}, "timestamp": {"timeInSeconds": newer_ts}, "quality": "GOOD"}],
    }])
    assert put_newer["errorEntries"] == [], f"expected no error entries, got {put_newer['errorEntries']}"
    latest_after_newer = _poll_get_property_value_by_alias(ctx, alias, expect_timestamp=newer_ts)
    assert latest_after_newer["value"]["doubleValue"] == 70.0, (
        f"expected 70.0, got {latest_after_newer['value']['doubleValue']}"
    )

    put_older = sw.batch_put_asset_property_value(entries=[{
        "entryId": "older-second",
        "propertyAlias": alias,
        "propertyValues": [{"value": {"doubleValue": 60.0}, "timestamp": {"timeInSeconds": older_ts}, "quality": "UNCERTAIN"}],
    }])
    assert put_older["errorEntries"] == [], f"expected no error entries, got {put_older['errorEntries']}"
    # the older-but-later-ingested sample must land in history...
    history = _poll_history_len(sw, asset_id, property_id, ts - 5, newer_ts + 5, expected_len=3)
    by_ts = {h["timestamp"]["timeInSeconds"]: h for h in history}
    assert by_ts[older_ts]["quality"] == "UNCERTAIN", f"expected UNCERTAIN, got {by_ts[older_ts]['quality']}"
    assert by_ts[older_ts]["value"]["doubleValue"] == 60.0, (
        f"expected 60.0, got {by_ts[older_ts]['value']['doubleValue']}"
    )
    # ...but "latest" must still be the truly-latest timestamp (newer_ts), unaffected by the
    # later ingestion of an older sample.
    still_latest = sw.get_asset_property_value(propertyAlias=alias)["propertyValue"]
    assert still_latest["timestamp"]["timeInSeconds"] == newer_ts, still_latest
    assert still_latest["value"]["doubleValue"] == 70.0, still_latest

    # history is chronologically ordered by timestamp, independent of ingestion order.
    timestamps_in_order = [h["timestamp"]["timeInSeconds"] for h in history]
    assert timestamps_in_order == sorted(timestamps_in_order), timestamps_in_order
    assert timestamps_in_order == [ts, older_ts, newer_ts], timestamps_in_order


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


def _disassociate_alias_best_effort(ctx, alias, asset_id, property_id):
    sw = ctx.client("iotsitewise")
    try:
        sw.disassociate_time_series_from_asset_property(alias=alias, assetId=asset_id, propertyId=property_id)
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
        tags={"sim2real": CHECK},
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
    resp = sw.create_asset(assetName=asset_name, assetModelId=model_id, tags={"sim2real": CHECK})
    asset_id = resp["assetId"]
    ctx.on_cleanup(lambda: _delete_asset_best_effort(ctx, asset_id))
    _wait_asset_active(ctx, asset_id)
    return asset_id


def _poll_time_series_by_alias(ctx, alias, asset_id, property_id, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last_resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sw.describe_time_series(alias=alias)
            last_resp, last_err = resp, None
            if resp.get("assetId") == asset_id and resp.get("propertyId") == property_id:
                return resp
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(
        f"time series for alias {alias} never bound to asset {asset_id}/{property_id} "
        f"(last_resp={last_resp}, last_err={last_err})"
    )


def _poll_get_property_value_by_alias(ctx, alias, expect_timestamp, timeout_s=60.0, interval_s=3.0):
    sw = ctx.client("iotsitewise")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sw.get_asset_property_value(propertyAlias=alias)
            last = resp["propertyValue"]
            if last["timestamp"]["timeInSeconds"] == expect_timestamp:
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"value for alias {alias} at {expect_timestamp} never appeared (last={last})")


def _poll_history_len(sw, asset_id, property_id, start_s, end_s, expected_len, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sw.get_asset_property_value_history(
            assetId=asset_id, propertyId=property_id, startDate=start_s, endDate=end_s,
        )["assetPropertyValueHistory"]
        if len(last) == expected_len:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"history never reached expected length {expected_len} (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

