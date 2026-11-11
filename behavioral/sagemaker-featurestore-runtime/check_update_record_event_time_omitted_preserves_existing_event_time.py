"""update-record-event-time-omitted-preserves-existing-event-time."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-record-event-time-omitted-preserves-existing-event-time"
GROUP = "state-transitions"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateRecord without EventTime keeps the stored EventTime and applies the feature value, and a
    later UpdateRecord with an older EventTime fails with ConflictException and the exact message,
    leaving the record unchanged."""
    fg_name = _create_online_feature_group(ctx)
    t1 = time.time()
    _put_record(ctx, fg_name, "rec-noet", t1, {"feature_a": "a1", "feature_b": "b1"})

    def probe_initial():
        return _get_record_dict(ctx, fg_name, "rec-noet")

    initial = _poll_until(probe_initial, lambda r: r is not None and r.get("feature_a") == "a1", timeout_s=30.0)
    initial_event_time = initial["event_time"]

    fsr = ctx.client("sagemaker-featurestore-runtime")
    # No EventTime supplied: feature_a changes, but the record's EventTime should stay t1.
    fsr.update_record(
        FeatureGroupName=fg_name,
        RecordIdentifierValueAsString="rec-noet",
        Features=[{"FeatureName": "feature_a", "ValueAsString": "a2"}],
    )

    def probe_after_first_update():
        return _get_record_dict(ctx, fg_name, "rec-noet")

    after_first = _poll_until(
        probe_after_first_update, lambda r: r is not None and r.get("feature_a") == "a2", timeout_s=30.0
    )
    # Directly confirms the target's OWN reported EventTime did not move, rather than inferring it
    # from a later conflict outcome that would be identical whether the store preserved t1 or
    # silently advanced it to some later "now" (both are newer than the stale probe below).
    assert after_first["event_time"] == initial_event_time, (
        f"expected EventTime to stay {initial_event_time!r} when omitted from UpdateRecord, "
        f"got {after_first['event_time']!r}"
    )
    assert after_first["feature_b"] == "b1", f"expected feature_b to remain 'b1', got {after_first['feature_b']!r}"

    # An EventTime equal to t1 minus a small delta must be rejected precisely because the stored
    # EventTime is still t1 (neither advanced by the omitted-EventTime update nor reset).
    code, message = _error(
        lambda: fsr.update_record(
            FeatureGroupName=fg_name,
            RecordIdentifierValueAsString="rec-noet",
            Features=[
                {"FeatureName": "event_time", "ValueAsString": str(t1 - 5)},
                {"FeatureName": "feature_b", "ValueAsString": "b2"},
            ],
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = (
        "Update rejected: the provided EventTime is older than the record's current EventTime. "
        "The record was not modified."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = _get_record_dict(ctx, fg_name, "rec-noet")
    assert unchanged["feature_b"] == "b1", "feature_b must be unaffected by the rejected stale update"
    assert unchanged["feature_a"] == "a2", f"expected feature_a to remain 'a2', got {unchanged['feature_a']!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    online_store_config = {"EnableOnlineStore": True, "StorageType": "Standard_V2"}
    if ttl_duration is not None:
        online_store_config["TtlDuration"] = ttl_duration
    sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=feature_defs,
        OnlineStoreConfig=online_store_config,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-fsr"}],
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
