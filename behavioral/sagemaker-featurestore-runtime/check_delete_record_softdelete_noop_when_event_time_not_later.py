"""delete-record-softdelete-noop-when-event-time-not-later."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-record-softdelete-noop-when-event-time-not-later"
GROUP = "state-transitions"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SoftDelete whose EventTime is not later than the record's current EventTime is
    a no-op for the OnlineStore: the call succeeds but the record remains fully intact
    and retrievable."""
    fg_name = _create_online_feature_group(ctx)
    t_current = time.time()
    _put_record(ctx, fg_name, "rec-noop", t_current, {"feature_a": "still-here"})

    def probe_exists():
        return _get_record_dict(ctx, fg_name, "rec-noop")

    _poll_until(probe_exists, lambda r: r is not None and r.get("feature_a") == "still-here", timeout_s=30.0)

    fsr = ctx.client("sagemaker-featurestore-runtime")
    t_stale = t_current - 500
    # SoftDelete with an EventTime older than the record's current EventTime: call succeeds
    # (no ValidationError), but per documented semantics it must not delete the record.
    fsr.delete_record(
        FeatureGroupName=fg_name,
        RecordIdentifierValueAsString="rec-noop",
        EventTime=str(t_stale),
        DeletionMode="SoftDelete",
    )

    # Freeze detector, not a fixed sleep: the stale SoftDelete must never take effect, so
    # repeated independent reads spread over a bounded window must all agree the record is
    # still there rather than merely "still there right now".
    def probe_still_present():
        r = _get_record_dict(ctx, fg_name, "rec-noop")
        assert r is not None, "stale SoftDelete must not remove the OnlineStore record"
        assert r["feature_a"] == "still-here", f"expected feature_a='still-here', got {r!r}"
        return r

    confirmations = _confirm_unchanged(probe_still_present, window_s=15.0, interval_s=2.0)
    assert confirmations >= 5, f"expected at least 5 confirming reads, got {confirmations}"


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


def _confirm_unchanged(probe, window_s, interval_s):
    """Call probe() repeatedly over a bounded window; probe itself asserts each read.
    Returns the number of confirming reads taken."""
    deadline = time.monotonic() + window_s
    count = 0
    while time.monotonic() < deadline:
        probe()
        count += 1
        time.sleep(interval_s)
    return count


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
