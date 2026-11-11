"""delete-record-harddelete-stale-event-time-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-record-harddelete-stale-event-time-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteRecord with DeletionMode=HardDelete and an EventTime not later than the
    record's current EventTime is rejected with ValidationError, and the record remains
    fully intact; a HardDelete with a later EventTime succeeds and removes it."""
    fg_name = _create_online_feature_group(ctx)
    t_current = time.time()
    _put_record(ctx, fg_name, "rec-hd-stale", t_current, {"feature_a": "still-here"})

    fsr = ctx.client("sagemaker-featurestore-runtime")

    def probe_initial():
        return _get_record_dict(ctx, fg_name, "rec-hd-stale")

    _poll_until(probe_initial, lambda r: r is not None, timeout_s=30.0)

    stale_time = t_current - 500
    code, message = _error(
        lambda: fsr.delete_record(
            FeatureGroupName=fg_name,
            RecordIdentifierValueAsString="rec-hd-stale",
            EventTime=str(stale_time),
            DeletionMode="HardDelete",
        )
    )
    assert code == "ValidationError", f"expected ValidationError for a stale HardDelete, got {code!r}"
    expected = "Validation Error: Delete event time must be same or after latest record event time."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_present = _get_record_dict(ctx, fg_name, "rec-hd-stale")
    assert still_present is not None, "the rejected stale HardDelete removed the record"
    assert still_present["feature_a"] == "still-here", (
        f"expected feature_a to remain 'still-here' after the rejected stale HardDelete, "
        f"got {still_present.get('feature_a')!r}"
    )

    fresh_time = t_current + 500
    fsr.delete_record(
        FeatureGroupName=fg_name,
        RecordIdentifierValueAsString="rec-hd-stale",
        EventTime=str(fresh_time),
        DeletionMode="HardDelete",
    )

    def probe_gone():
        return _get_record_dict(ctx, fg_name, "rec-hd-stale")

    _poll_until(probe_gone, lambda r: r is None, timeout_s=30.0)


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available."""
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
    online_store_config = {"EnableOnlineStore": True}
    if ttl_duration is not None:
        online_store_config["TtlDuration"] = ttl_duration
    sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=feature_defs,
        OnlineStoreConfig=online_store_config,
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
