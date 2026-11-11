"""batch-write-record-bulk-ingestion-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-write-record-bulk-ingestion-round-trip"
GROUP = "batch-operations"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteRecord ingests entries targeting two different FeatureGroups in one
    call, and every entry is individually retrievable afterwards via GetRecord, matching
    PutRecord's per-entry write semantics."""
    fg1 = _create_online_feature_group(ctx)
    fg2 = _create_online_feature_group(ctx)
    t0 = time.time()

    fsr = ctx.client("sagemaker-featurestore-runtime")
    resp = fsr.batch_write_record(
        Entries=[
            {
                "FeatureGroupName": fg1,
                "Record": [
                    {"FeatureName": "record_id", "ValueAsString": "rec-bw1"},
                    {"FeatureName": "event_time", "ValueAsString": str(t0)},
                    {"FeatureName": "feature_a", "ValueAsString": "bulk-1"},
                ],
            },
            {
                "FeatureGroupName": fg2,
                "Record": [
                    {"FeatureName": "record_id", "ValueAsString": "rec-bw2"},
                    {"FeatureName": "event_time", "ValueAsString": str(t0)},
                    {"FeatureName": "feature_a", "ValueAsString": "bulk-2"},
                ],
            },
        ]
    )
    assert resp["Errors"] == [], f"expected no per-entry errors, got {resp['Errors']!r}"
    assert resp["UnprocessedEntries"] == [], f"expected no unprocessed entries, got {resp['UnprocessedEntries']!r}"

    def probe1():
        return _get_record_dict(ctx, fg1, "rec-bw1")

    def probe2():
        return _get_record_dict(ctx, fg2, "rec-bw2")

    r1 = _poll_until(probe1, lambda r: r is not None, timeout_s=30.0)
    r2 = _poll_until(probe2, lambda r: r is not None, timeout_s=30.0)
    assert r1["record_id"] == "rec-bw1", f"expected record_id=rec-bw1, got {r1.get('record_id')!r}"
    assert r1["feature_a"] == "bulk-1", f"expected feature_a=bulk-1, got {r1.get('feature_a')!r}"
    assert r2["record_id"] == "rec-bw2", f"expected record_id=rec-bw2, got {r2.get('record_id')!r}"
    assert r2["feature_a"] == "bulk-2", f"expected feature_a=bulk-2, got {r2.get('feature_a')!r}"


def _wait_for_feature_group_status(ctx, name, target_status, timeout_s=300.0, interval_s=5.0):
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = sm.describe_feature_group(FeatureGroupName=name)
        last = desc.get("FeatureGroupStatus")
        if last == target_status:
            return desc
        if last in ("CreateFailed", "DeleteFailed"):
            raise AssertionError(f"feature group {name} entered {last}: {desc.get('FailureReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"feature group {name} did not reach {target_status} within {timeout_s}s (last={last})")


def _safe_delete_feature_group(ctx, name):
    try:
        ctx.client("sagemaker").delete_feature_group(FeatureGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _create_online_feature_group(ctx, extra_features=None, ttl_duration=None):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-fsr-")
    feature_defs = [
        {"FeatureName": "record_id", "FeatureType": "String"},
        {"FeatureName": "event_time", "FeatureType": "Fractional"},
    ] + (
        extra_features
        or [
            {"FeatureName": "feature_a", "FeatureType": "String"},
            {"FeatureName": "feature_b", "FeatureType": "String"},
            {"FeatureName": "feature_c", "FeatureType": "String"},
        ]
    )
    online_store_config = {"EnableOnlineStore": True}
    if ttl_duration is not None:
        online_store_config["TtlDuration"] = ttl_duration
    sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=feature_defs,
        OnlineStoreConfig=online_store_config,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_feature_group(ctx, name))
    _wait_for_feature_group_status(ctx, name, "Created")
    return name


def _get_record_dict(ctx, fg_name, record_id, **kwargs):
    fsr = ctx.client("sagemaker-featurestore-runtime")
    resp = fsr.get_record(FeatureGroupName=fg_name, RecordIdentifierValueAsString=record_id, **kwargs)
    record = resp.get("Record")
    if record is None:
        return None
    return {fv["FeatureName"]: fv.get("ValueAsString") for fv in record}


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
