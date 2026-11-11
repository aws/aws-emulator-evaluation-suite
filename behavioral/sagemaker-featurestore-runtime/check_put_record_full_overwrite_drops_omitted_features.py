"""put-record-full-overwrite-drops-omitted-features."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-full-overwrite-drops-omitted-features"
GROUP = "state-transitions"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A later PutRecord fully replaces the OnlineStore row: a feature omitted from the
    newer Record disappears from GetRecord output rather than being merged/retained
    (unlike UpdateRecord's partial-update semantics)."""
    fg_name = _create_online_feature_group(ctx)
    t1 = time.time()
    _put_record(ctx, fg_name, "rec-ovw", t1, {"feature_a": "v1", "feature_b": "v1"})

    def probe_initial():
        return _get_record_dict(ctx, fg_name, "rec-ovw")

    initial = _poll_until(probe_initial, lambda r: r is not None and r.get("feature_b") == "v1", timeout_s=30.0)
    assert initial["feature_a"] == "v1", f"expected initial feature_a='v1', got {initial}"

    t2 = t1 + 10
    # second write omits feature_b entirely
    _put_record(ctx, fg_name, "rec-ovw", t2, {"feature_a": "v2"})

    def probe_final():
        return _get_record_dict(ctx, fg_name, "rec-ovw")

    final = _poll_until(probe_final, lambda r: r is not None and r.get("feature_a") == "v2", timeout_s=30.0)
    assert "feature_b" not in final, f"expected feature_b to be dropped by full overwrite, got {final}"


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
