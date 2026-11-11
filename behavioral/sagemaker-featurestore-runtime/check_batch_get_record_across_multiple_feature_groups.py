"""batch-get-record-across-multiple-feature-groups."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-get-record-across-multiple-feature-groups"
GROUP = "batch-operations"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetRecord retrieves records spanning two different FeatureGroups in a single
    call, correctly attributing each result to its own FeatureGroupName."""
    fg1 = _create_online_feature_group(ctx)
    fg2 = _create_online_feature_group(ctx)
    t0 = time.time()
    _put_record(ctx, fg1, "rec-x", t0, {"feature_a": "from-fg1"})
    _put_record(ctx, fg2, "rec-y", t0, {"feature_a": "from-fg2"})

    fsr = ctx.client("sagemaker-featurestore-runtime")

    def probe():
        resp = fsr.batch_get_record(
            Identifiers=[
                {"FeatureGroupName": fg1, "RecordIdentifiersValueAsString": ["rec-x"]},
                {"FeatureGroupName": fg2, "RecordIdentifiersValueAsString": ["rec-y"]},
            ]
        )
        return resp["Records"]

    records = _poll_until(probe, lambda recs: len(recs) == 2, timeout_s=30.0)

    by_fg = {r["FeatureGroupName"]: r for r in records}
    assert set(by_fg) == {fg1, fg2}, f"expected records for exactly {{fg1, fg2}}, got {sorted(by_fg)}"
    assert by_fg[fg1]["RecordIdentifierValueAsString"] == "rec-x", (
        f"expected rec-x for {fg1}, got {by_fg[fg1]['RecordIdentifierValueAsString']!r}"
    )
    assert by_fg[fg2]["RecordIdentifierValueAsString"] == "rec-y", (
        f"expected rec-y for {fg2}, got {by_fg[fg2]['RecordIdentifierValueAsString']!r}"
    )
    values1 = {fv["FeatureName"]: fv["ValueAsString"] for fv in by_fg[fg1]["Record"]}
    values2 = {fv["FeatureName"]: fv["ValueAsString"] for fv in by_fg[fg2]["Record"]}
    assert values1["feature_a"] == "from-fg1", (
        f"expected feature_a=from-fg1 for {fg1}, got {values1.get('feature_a')!r}"
    )
    assert values2["feature_a"] == "from-fg2", (
        f"expected feature_a=from-fg2 for {fg2}, got {values2.get('feature_a')!r}"
    )


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


def _put_record(ctx, fg_name, record_id, event_time, features, ttl_duration=None):
    fsr = ctx.client("sagemaker-featurestore-runtime")
    record = [
        {"FeatureName": "record_id", "ValueAsString": record_id},
        {"FeatureName": "event_time", "ValueAsString": str(event_time)},
    ] + [{"FeatureName": k, "ValueAsString": v} for k, v in features.items()]
    kwargs = {"FeatureGroupName": fg_name, "Record": record}
    if ttl_duration is not None:
        kwargs["TtlDuration"] = ttl_duration
    fsr.put_record(**kwargs)


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
